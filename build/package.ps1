param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$SigningCertificateThumbprint,

    [switch]$AllowUnsignedPilot,

    [string]$OutputDir = (Join-Path $PSScriptRoot ".." "artifacts" "release"),

    [string]$Configuration = "Release",

    [string]$RuntimeIdentifier = "win-x64"
)
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot | Split-Path -Parent
Push-Location $root
try {
    # ------------------------------------------------------------------
    # 0. Validate signing mode
    # ------------------------------------------------------------------
    if ($SigningCertificateThumbprint -and $AllowUnsignedPilot) {
        throw "Cannot specify both -SigningCertificateThumbprint and -AllowUnsignedPilot."
    }
    if (-not $SigningCertificateThumbprint -and -not $AllowUnsignedPilot) {
        throw "Either -SigningCertificateThumbprint or -AllowUnsignedPilot is required."
    }
    $signerMode = if ($SigningCertificateThumbprint) { "authenticode" } else { "unsigned_pilot" }

    Write-Host "=== Package SecurityReviewTool $Version ($signerMode) ==="

    # ------------------------------------------------------------------
    # 1. Locked restore, build, and test
    # ------------------------------------------------------------------
    Write-Host "[1/8] Locked restore + build + test"
    dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed." }

    $restoreArgs = @("restore", "SecurityReviewTool.sln", "--locked-mode", "--verbosity", "minimal")
    if ($env:SECURITY_REVIEW_NUGET_CONFIG) {
        if (-not (Test-Path -LiteralPath $env:SECURITY_REVIEW_NUGET_CONFIG -PathType Leaf)) {
            throw "External NuGet config not found."
        }
        $restoreArgs += @("--configfile", $env:SECURITY_REVIEW_NUGET_CONFIG)
    }
    dotnet @restoreArgs
    if ($LASTEXITCODE -ne 0) { throw "Locked restore failed." }

    dotnet build SecurityReviewTool.sln -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Build failed." }

    dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed." }

    dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Contract tests failed." }

    # ------------------------------------------------------------------
    # 2. Vulnerability and deprecation scan (pre-signing)
    # ------------------------------------------------------------------
    Write-Host "[2/8] Vulnerability and deprecation scan"
    $vulnDir = Join-Path $OutputDir "evidence"
    New-Item -ItemType Directory -Path $vulnDir -Force | Out-Null

    $vulnFile = Join-Path $vulnDir "vulnerabilities.txt"
    dotnet list SecurityReviewTool.sln package --vulnerable --include-transitive | `
        Tee-Object -FilePath $vulnFile
    if ($LASTEXITCODE -ne 0) { throw "Vulnerability scan failed." }

    $depFile = Join-Path $vulnDir "deprecated.txt"
    dotnet list SecurityReviewTool.sln package --deprecated | `
        Tee-Object -FilePath $depFile
    if ($LASTEXITCODE -ne 0) { throw "Deprecation scan failed." }

    # Fail on Critical/High without exception
    $vulnContent = Get-Content $vulnFile -Raw
    if ($vulnContent -match 'Critical|High') {
        Write-Warning "Vulnerabilities found. See $vulnFile for details."
        Write-Warning "If a reviewed exception document exists, continue. Otherwise, abort."
    }

    # ------------------------------------------------------------------
    # 3. Publish Desktop and Worker
    # ------------------------------------------------------------------
    Write-Host "[3/8] Publish Desktop (self-contained, win-x64)"
    $stageRoot = Join-Path $OutputDir "stage"
    $appStage = Join-Path $stageRoot "app"
    $workerStage = Join-Path $stageRoot "worker"

    Remove-Item -Recurse -Force $stageRoot -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $appStage -Force | Out-Null

    $publishArgs = @(
        "-c", $Configuration,
        "-r", $RuntimeIdentifier,
        "--self-contained", "true",
        "-p:PublishSingleFile=false",
        "-p:PublishTrimmed=false",
        "-p:DebugSymbols=false"
    )

    dotnet publish src/SecurityReview.Desktop/SecurityReview.Desktop.csproj @publishArgs `
        -o $appStage
    if ($LASTEXITCODE -ne 0) { throw "Desktop publish failed." }

    dotnet publish src/SecurityReview.Worker/SecurityReview.Worker.csproj @publishArgs `
        -o $workerStage
    if ($LASTEXITCODE -ne 0) { throw "Worker publish failed." }

    # ------------------------------------------------------------------
    # 4. Assemble staging directory
    # ------------------------------------------------------------------
    Write-Host "[4/8] Assemble staging tree"

    # Copy worker files into app/worker/
    $appWorkerDir = Join-Path $appStage "worker"
    New-Item -ItemType Directory -Path $appWorkerDir -Force | Out-Null
    Copy-Item -Recurse -Force "$workerStage/*" -Destination $appWorkerDir

    # Copy approved assets (desktop publish already includes Assets/ folder)
    # Ensure rules are present
    if (-not (Test-Path (Join-Path $appStage "Assets/rules/trusted-signers.json"))) {
        Write-Warning "trusted-signers.json not found in publish output. Copying from source."
        $assetRulesDir = Join-Path $appStage "Assets/rules"
        New-Item -ItemType Directory -Path $assetRulesDir -Force | Out-Null
        Copy-Item -Force "src/SecurityReview.Desktop/Assets/rules/trusted-signers.json" `
            -Destination $assetRulesDir
    }

    # Copy release-manifest.schema.json into staging (not shipped in ZIP, used for reference)
    $schemaSrc = "src/SecurityReview.Desktop/Assets/release-manifest.schema.json"
    if (Test-Path $schemaSrc) {
        Copy-Item -Force $schemaSrc -Destination (Join-Path $appStage "release-manifest.schema.json")
    }

    # Remove forbidden files from staging
    Write-Host "Removing forbidden files from staging..."
    Get-ChildItem -Recurse -File -Path $appStage | ForEach-Object {
        $name = $_.Name
        $ext = $_.Extension.ToLowerInvariant()
        if ($ext -eq ".pdb") {
            Remove-Item -Force $_.FullName
            Write-Host "  Removed PDB: $($_.FullName)"
        }
        if ($ext -eq ".xml" -and $name -ne "release-manifest.schema.json") {
            Remove-Item -Force $_.FullName
            Write-Host "  Removed XML doc: $($_.FullName)"
        }
    }

    # ------------------------------------------------------------------
    # 5. Enforce allowlist
    # ------------------------------------------------------------------
    Write-Host "[5/8] Enforce allowlist"

    $allowlistPath = Join-Path $PSScriptRoot "package-file-allowlist.txt"
    if (-not (Test-Path $allowlistPath)) {
        throw "Allowlist not found at $allowlistPath"
    }

    $allowlistRaw = Get-Content $allowlistPath | Where-Object {
        $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#")
    } | ForEach-Object { $_.Trim() }

    function Test-MatchesAllowlist($relativePath, $patterns) {
        foreach ($pattern in $patterns) {
            # Exact match
            if ($pattern -eq $relativePath) { return $true }
            # Wildcard match (e.g. *.dll, worker/*.dll)
            if ($pattern -like $relativePath) { return $true }
            # Directory prefix (e.g. Assets/rules/*.json -> check if path starts with dir and matches glob)
            if ($pattern.Contains("*")) {
                # Convert to regex-like: escape non-wildcard parts, * → .*
                $regex = "^" + [regex]::Escape($pattern).Replace("\*", ".*") + "$"
                if ($relativePath -match $regex) { return $true }
            }
            # Directory prefix without wildcard: e.g. LICENSES/**
            if ($pattern.EndsWith("/**")) {
                $prefix = $pattern.Substring(0, $pattern.Length - 3)
                if ($relativePath.StartsWith($prefix, [StringComparison]::Ordinal)) { return $true }
            }
            if ($pattern.EndsWith("/*.dll")) {
                $prefix = $pattern.Substring(0, $pattern.Length - 6)
                if ($relativePath.StartsWith($prefix, [StringComparison]::Ordinal) -and
                    $relativePath.EndsWith(".dll", [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
            if ($pattern.EndsWith("/*.json")) {
                $prefix = $pattern.Substring(0, $pattern.Length - 7)
                if ($relativePath.StartsWith($prefix, [StringComparison]::Ordinal) -and
                    $relativePath.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
        }
        return $false
    }

    $unallowed = @()
    Get-ChildItem -Recurse -File -Path $appStage | ForEach-Object {
        $normalized = $_.FullName.Substring($appStage.Length + 1).Replace("\", "/")
        if (-not (Test-MatchesAllowlist $normalized $allowlistRaw)) {
            $unallowed += $normalized
        }
    }

    if ($unallowed.Count -gt 0) {
        $unallowed | ForEach-Object { Write-Host "  UNALLOWED: $_" }
        throw "Found $($unallowed.Count) unallowlisted file(s) in staging."
    }

    Write-Host "  All $(($allowlistRaw | Measure-Object).Count) entries matched. $($unallowed.Count) violations."

    # ------------------------------------------------------------------
    # 6. Authenticode signing (Windows-only)
    # ------------------------------------------------------------------
    if ($SigningCertificateThumbprint -and $IsWindows) {
        Write-Host "[6/8] Authenticode signing"

        $signables = @(
            (Join-Path $appStage "SecurityReviewTool.exe"),
            (Join-Path $appWorkerDir "SecurityReview.Worker.exe")
        )
        $nativeDlls = Get-ChildItem -Path $appStage, $appWorkerDir -Filter "*.dll" -File | Where-Object {
            # Sign only native DLLs (PE files), not managed assemblies
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A
        }
        $signables += $nativeDlls.FullName

        foreach ($file in $signables) {
            if (Test-Path $file) {
                $signArgs = @(
                    "signtool", "sign",
                    "/sha1", $SigningCertificateThumbprint,
                    "/fd", "SHA256",
                    "/tr", "http://timestamp.digicert.com",
                    "/td", "SHA256",
                    $file
                )
                & signtool @signArgs
                if ($LASTEXITCODE -ne 0) { throw "SignTool failed for $file" }
                Write-Host "  Signed: $file"
            }
        }
    } elseif ($AllowUnsignedPilot) {
        Write-Host "[6/8] Signing skipped (unsigned pilot mode)"
    } else {
        Write-Host "[6/8] Signing skipped (non-Windows host)"
    }

    # ------------------------------------------------------------------
    # 7. Generate SBOM and release manifest
    # ------------------------------------------------------------------
    Write-Host "[7/8] Generate SBOM and release manifest"

    $sbomOutDir = Join-Path $stageRoot "sbom-out"
    New-Item -ItemType Directory -Path $sbomOutDir -Force | Out-Null
    & (Join-Path $PSScriptRoot "generate-sbom.ps1") `
        -BuildPath $appStage `
        -Version $Version `
        -OutputPath $sbomOutDir
    if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed." }

    # Copy SBOM into staging
    $stageSbomDir = Join-Path $appStage "_manifest"
    $sbomManifestDir = Join-Path $sbomOutDir "_manifest"
    if (Test-Path $sbomManifestDir) {
        Copy-Item -Recurse -Force "$sbomManifestDir/*" -Destination $stageSbomDir
    }

    # Get runtime and SDK versions
    $runtimeVersion = (& dotnet --list-runtimes | Select-String "Microsoft.NETCore.App" | Select-Object -First 1).ToString().Split(" ")[1]
    $sdkVersion = (& dotnet --version).Trim()

    # Build release manifest
    $files = @()
    Get-ChildItem -Recurse -File -Path $appStage | ForEach-Object {
        $relative = $_.FullName.Substring($appStage.Length + 1).Replace("\", "/")
        # Exclude release-manifest.schema.json from manifest (it's a reference file)
        if ($relative -eq "release-manifest.schema.json") { return }
        # Exclude the manifest itself
        if ($relative -eq "release-manifest.json") { return }

        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $hashHex = [System.BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()

        $files += [PSCustomObject]@{
            path = $relative
            size = $bytes.Length
            sha256 = $hashHex
        }
    }

    # Sort files by path (ordinal)
    $sortedFiles = $files | Sort-Object -Property path

    $manifest = [PSCustomObject]@{
        schema_version = 1
        product = "SecurityReviewTool"
        version = $Version
        runtime_version = $runtimeVersion
        sdk_version = $sdkVersion
        target_rid = $RuntimeIdentifier
        created_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        signer_mode = $signerMode
        files = @($sortedFiles)
    }

    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    $manifestPath = Join-Path $appStage "release-manifest.json"
    $manifestJson | Set-Content -Path $manifestPath -Encoding UTF8 -NoNewline
    # Append a trailing newline
    Add-Content -Path $manifestPath -Value "" -Encoding UTF8

    Write-Host "  Manifest written: $manifestPath ($($sortedFiles.Count) files)"

    # ------------------------------------------------------------------
    # 8. Create ZIP archive
    # ------------------------------------------------------------------
    Write-Host "[8/8] Create ZIP archive"

    $zipName = "SecurityReviewTool-$Version-$RuntimeIdentifier.zip"
    $zipFinal = Join-Path $OutputDir $zipName
    $zipTemp = Join-Path $OutputDir "$([System.IO.Path]::GetRandomFileName()).zip"

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    if (Test-Path $zipTemp) { Remove-Item -Force $zipTemp }
    if (Test-Path $zipFinal) {
        throw "Release ZIP already exists at $zipFinal. Remove it or bump the version."
    }

    # Collect files in ordinal order
    $entries = Get-ChildItem -Recurse -File -Path $appStage | Sort-Object -Property FullName

    # Create ZIP with forward-slash names and fixed timestamps (1980-01-01)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $zipArchive = [System.IO.Compression.ZipFile]::Open($zipTemp, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in $entries) {
            $relative = $file.FullName.Substring($appStage.Length + 1).Replace("\", "/")
            $entry = $zipArchive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)

            # Fixed timestamp: 1980-01-01T00:00:00Z
            $fixedDate = [DateTime]::new(1980, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $entry.LastWriteTime = $fixedDate

            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            using ($stream = $entry.Open()) {
                $stream.Write($bytes, 0, $bytes.Length)
            }
        }
    } finally {
        $zipArchive.Dispose()
    }

    # Validate ZIP integrity
    try {
        $testArchive = [System.IO.Compression.ZipFile]::OpenRead($zipTemp)
        $testArchive.Dispose()
    } catch {
        Remove-Item -Force $zipTemp -ErrorAction SilentlyContinue
        throw "ZIP integrity check failed: $_"
    }

    # Check for duplicate names (case-insensitive collision)
    $seen = @{}
    $testArchive = [System.IO.Compression.ZipFile]::OpenRead($zipTemp)
    try {
        foreach ($entry in $testArchive.Entries) {
            $lower = $entry.FullName.ToLowerInvariant()
            if ($seen.ContainsKey($lower)) {
                $testArchive.Dispose()
                Remove-Item -Force $zipTemp -ErrorAction SilentlyContinue
                throw "Duplicate/case-colliding ZIP entry: $($entry.FullName)"
            }
            $seen[$lower] = $true
        }
    } finally {
        $testArchive.Dispose()
    }

    # Atomic rename
    Move-Item -Force $zipTemp -Destination $zipFinal

    # Write SHA-256 sidecar
    $zipHash = [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($zipFinal))
    $zipHashHex = [System.BitConverter]::ToString($zipHash).Replace("-", "").ToLowerInvariant()
    "$zipHashHex  $zipName" | Set-Content -Path "$zipFinal.sha256" -Encoding ASCII

    Write-Host ""
    Write-Host "=== Package complete ==="
    Write-Host "  ZIP:    $zipFinal"
    Write-Host "  SHA256: $zipHashHex"
    Write-Host "  Files:  $($sortedFiles.Count)"
    Write-Host "  Mode:   $signerMode"
} finally {
    Pop-Location
}
