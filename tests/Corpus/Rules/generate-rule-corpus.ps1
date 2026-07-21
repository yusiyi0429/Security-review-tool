#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Generates and validates the rule corpus manifest against fixtures.

.DESCRIPTION
  Computes SHA-256 hashes of all fixtures under tests/Corpus/Rules/fixtures/,
  updates the rule-corpus-manifest.json with current hashes, and runs the
  verify-rule-corpus command against the active rule pack.
#>
param(
    [string]$RulesPath = "artifacts/rules/security-review-rules-1.0.0.zip",
    [string]$ManifestPath = "tests/Corpus/Rules/rule-corpus-manifest.json",
    [string]$OutputPath = "artifacts/corpus/rule-results.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Step 1: Refresh SHA-256 hashes in the manifest
Write-Host "Computing fixture hashes..." -ForegroundColor Cyan
$fixturesDir = Join-Path $projectRoot "tests/Corpus/Rules/fixtures"
$manifestFile = Join-Path $projectRoot $ManifestPath

if (-not (Test-Path $manifestFile)) {
    Write-Error "Manifest not found: $manifestFile"
    exit 1
}

$manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json -Depth 10

foreach ($case in $manifest.cases) {
    $fixturePath = Join-Path $projectRoot "tests/Corpus/Rules" $case.fixturePath
    if (-not (Test-Path $fixturePath)) {
        Write-Warning "Fixture not found: $fixturePath, skipping hash update for $($case.caseId)"
        continue
    }
    $hash = (Get-FileHash -Path $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($case.sha256 -ne $hash) {
        Write-Host "  Updated $($case.caseId): $($case.sha256) -> $hash"
        $case.sha256 = $hash
    }
}

# Update rule-pack SHA-256 if rules exist
$rulesZip = Join-Path $projectRoot $RulesPath
if (Test-Path $rulesZip) {
    $packHash = (Get-FileHash -Path $rulesZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.rulePackSha256 = $packHash
    Write-Host "Rule pack SHA-256: $packHash"
}

# Save updated manifest
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestFile -Encoding UTF8
Write-Host "Manifest updated at $manifestFile" -ForegroundColor Green

# Step 2: Run verify-rule-corpus
Write-Host "Running verify-rule-corpus..." -ForegroundColor Cyan
$corpusTool = Join-Path $projectRoot "tools/SecurityReview.CorpusTool"

if (-not (Test-Path $rulesZip)) {
    Write-Host "WARNING: Rule pack not found at $rulesZip — skipping verification run." -ForegroundColor Yellow
    Write-Host "Run: dotnet run --project $corpusTool -c Release -- verify-rule-corpus --rules $RulesPath --manifest $ManifestPath --output $OutputPath"
    exit 0
}

$outputDir = Split-Path -Parent (Join-Path $projectRoot $OutputPath)
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$exitCode = 0
dotnet run --project $corpusTool -c Release -- verify-rule-corpus `
    --rules (Join-Path $projectRoot $RulesPath) `
    --manifest $manifestFile `
    --output (Join-Path $projectRoot $OutputPath)

if ($LASTEXITCODE -ne 0) {
    Write-Error "verify-rule-corpus failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Rule corpus verification complete." -ForegroundColor Green
exit 0
