[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Corpus,

    [int]$Runs = 5,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$Configuration = "Release",

    [switch]$SkipHostCheck,
    [switch]$SkipCorpusCheck
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot\..
try {

# ── Prerequisites ────────────────────────────────────────────────────────
if (-not $SkipHostCheck) {
    if ($env:SECURITY_REVIEW_PERF_HOST -ne "1") {
        Write-Error "SECURITY_REVIEW_PERF_HOST is not set to 1. Set it or use -SkipHostCheck."
        exit 1
    }
}

if (-not $SkipCorpusCheck) {
    $manifestPath = Join-Path $Corpus "manifest.json"
    if (-not (Test-Path $manifestPath)) {
        Write-Error "Corpus manifest not found: $manifestPath. Generate corpus first with generate-large-corpus.ps1"
        exit 1
    }
    Write-Host "Corpus manifest found: $manifestPath"
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    Write-Host "  Seed: $($manifest.Seed)"
    Write-Host "  Corpus A: $($manifest.Corpora.A.ExpectedFiles) files, $([math]::Round($manifest.Corpora.A.ExpectedSizeBytes / 1GB, 2)) GiB"
}

# ── Build ────────────────────────────────────────────────────────────────
Write-Host "Building in $Configuration configuration ..."
& dotnet build tests/SecurityReview.PerformanceTests -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

# ── Output directory ────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$counterDir = Join-Path $Output "counters"
New-Item -ItemType Directory -Path $counterDir -Force | Out-Null

# ── Host snapshot ────────────────────────────────────────────────────────
Write-Host "Collecting host snapshot ..."
$hostSnapshot = @{
    TimestampUtc    = (Get-Date).ToUniversalTime().ToString("o")
    OsEdition       = (Get-CimInstance Win32_OperatingSystem).Caption
    OsBuild         = [System.Environment]::OSVersion.Version.ToString()
    CpuName         = (Get-CimInstance Win32_Processor).Name
    LogicalCores    = [System.Environment]::ProcessorCount
    TotalMemoryGiB  = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    FreeMemoryGiB   = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB / 1GB, 1)
    DotNetVersion   = (& dotnet --version)
    GitRevision     = (& git rev-parse HEAD)
}

try {
    $defenderStatus = Get-MpComputerStatus
    $hostSnapshot.DefenderRealTime = $defenderStatus.RealTimeProtectionEnabled
} catch {
    $hostSnapshot.DefenderRealTime = "unknown"
}

try {
    $powerPlan = powercfg /getactivescheme 2>$null
    if ($powerPlan -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
        $hostSnapshot.PowerPlanGuid = $matches[1]
    }
    $hostSnapshot.OnAcPower = ([System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -eq "Online")
} catch {
    $hostSnapshot.OnAcPower = "unknown"
}

try {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$((Get-Item $Corpus).PSDrive.Root)'"
    $hostSnapshot.FreeDiskGiB = [math]::Round($disk.FreeSpace / 1GB, 1)
} catch {
    $hostSnapshot.FreeDiskGiB = "unknown"
}

$hostSnapshotPath = Join-Path $Output "host-snapshot.json"
$hostSnapshot | ConvertTo-Json -Depth 3 | Out-File -FilePath $hostSnapshotPath -Encoding utf8
Write-Host "  Host snapshot: $hostSnapshotPath"

# ── Validate baseline ────────────────────────────────────────────────────
$referencePath = Join-Path $PSScriptRoot ".." "tests" "Performance" "reference-host.json"
if (Test-Path $referencePath) {
    $reference = Get-Content $referencePath -Raw | ConvertFrom-Json
    $baseline = $reference.baseline

    $warnings = @()
    if ($hostSnapshot.LogicalCores -lt $baseline.cpu.minimumLogicalCores) {
        $warnings += "CPU cores: $($hostSnapshot.LogicalCores) < $($baseline.cpu.minimumLogicalCores)"
    }
    if ($hostSnapshot.TotalMemoryGiB -lt $baseline.memory.minimumTotalGiB) {
        $warnings += "RAM: $($hostSnapshot.TotalMemoryGiB) GiB < $($baseline.memory.minimumTotalGiB) GiB"
    }
    if ($hostSnapshot.FreeDiskGiB -ne "unknown" -and $hostSnapshot.FreeDiskGiB -lt $baseline.storage.minimumFreeSpaceGiB) {
        $warnings += "Free disk: $($hostSnapshot.FreeDiskGiB) GiB < $($baseline.storage.minimumFreeSpaceGiB) GiB"
    }

    if ($warnings.Count -gt 0) {
        Write-Host "⚠ BASELINE WARNINGS:" -ForegroundColor Yellow
        foreach ($w in $warnings) { Write-Host "  - $w" -ForegroundColor Yellow }
        if ($reference.validation.rejectIfBelowBaseline) {
            Write-Error "Host is below performance baseline. Rejecting run. Use -SkipHostCheck to override."
            exit 1
        }
    } else {
        Write-Host "✓ Host meets performance baseline" -ForegroundColor Green
    }
}

# ── Run performance test suite ───────────────────────────────────────────
Write-Host ""
Write-Host "Running performance tests ($Runs runs) ..."
Write-Host ""

$testProject = "tests/SecurityReview.PerformanceTests"

# Run each test category separately for clean TRX output
$testSuites = @(
    @{ Name = "Startup";        Filter = "FullyQualifiedName~StartupPerformance";        Env = @{} },
    @{ Name = "LargeScan";      Filter = "FullyQualifiedName~LargeScanPerformance";       Env = @{ CORPUS_ROOT = $Corpus } },
    @{ Name = "MemoryScaling";  Filter = "FullyQualifiedName~MemoryScaling";              Env = @{ CORPUS_ROOT = $Corpus } },
    @{ Name = "FaultInjection"; Filter = "FullyQualifiedName~FaultInjection";             Env = @{ CORPUS_ROOT = $Corpus } },
    @{ Name = "UiResponsiveness"; Filter = "FullyQualifiedName~UiResponsiveness";         Env = @{ CORPUS_ROOT = $Corpus } }
)

$allPassed = $true
$results = @{}

foreach ($suite in $testSuites) {
    Write-Host "--- $($suite.Name) ---"

    $trxPath = Join-Path $Output "$($suite.Name).trx"
    $envBlock = @{
        SECURITY_REVIEW_PERF_HOST = "1"
        SECURITY_REVIEW_PERF_RUNS = $Runs.ToString()
        SECURITY_REVIEW_PERF_OUTPUT = $counterDir
    }

    foreach ($kv in $suite.Env.GetEnumerator()) {
        $envBlock[$kv.Key] = $kv.Value
    }

    # Build env var arguments
    $envArgs = @()
    foreach ($kv in $envBlock.GetEnumerator()) {
        $envArgs += "--"
        $envArgs += "environment"
        $envArgs += "$($kv.Key)=$($kv.Value)"
    }

    & dotnet test $testProject `
        -c $Configuration `
        --no-build `
        --filter $suite.Filter `
        --logger "trx;LogFileName=$($suite.Name).trx" `
        --results-directory $Output `
        $envArgs

    $passed = $LASTEXITCODE -eq 0
    $results[$suite.Name] = $passed
    if (-not $passed) { $allPassed = $false }
    Write-Host ""
}

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host "========================================"
Write-Host "Performance Test Summary" -ForegroundColor Cyan
Write-Host "========================================"
foreach ($kv in $results.GetEnumerator()) {
    $color = if ($kv.Value) { "Green" } else { "Red" }
    $status = if ($kv.Value) { "PASS" } else { "FAIL" }
    Write-Host "  $($kv.Name): $status" -ForegroundColor $color
}

Write-Host ""
Write-Host "Output directory : $Output"
Write-Host "Counter files    : $counterDir"
Write-Host "Host snapshot    : $hostSnapshotPath"
Write-Host "Overall          : $(if ($allPassed) { 'PASS' } else { 'FAIL' })"

if (-not $allPassed) {
    exit 1
}

} finally {
    Pop-Location
}
