param()
$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot | Split-Path -Parent

$prdPath   = Join-Path $repoRoot "docs/prd/prd-security-asset-content-review-tool.md"
$srsPath   = Join-Path $repoRoot "docs/srs/srs-security-asset-content-review-tool.md"
$manifestPath = Join-Path $repoRoot "tests/Acceptance/acceptance-manifest.json"

# ------------------------------------------------------------------
# 1. Check that the required files exist
# ------------------------------------------------------------------
$errors = @()

if (-not (Test-Path $prdPath))   { $errors += "Missing PRD: $prdPath"; }
if (-not (Test-Path $srsPath))   { $errors += "Missing SRS: $srsPath"; }
if (-not (Test-Path $manifestPath)) { $errors += "Missing manifest: $manifestPath"; }

if ($errors.Count -gt 0) {
    Write-Host "TRACE FAIL:"
    $errors | ForEach-Object { Write-Host "  $_" }
    exit 1
}

# ------------------------------------------------------------------
# 2. Define expected ID ranges
# ------------------------------------------------------------------
$expectedReqs  = 1..20  | ForEach-Object { "REQ-{0:D3}" -f $_ }
$expectedAcs   = 1..64  | ForEach-Object { "AC-{0:D3}"  -f $_ }
$expectedSrsFs = 1..20  | ForEach-Object { "SRS-F-{0:D3}" -f $_ }
$expectedVts   = 1..36  | ForEach-Object { "VT-{0:D3}"  -f $_ }

# ------------------------------------------------------------------
# 3. Extract IDs from PRD and SRS markdown files
# ------------------------------------------------------------------
function Extract-IdsFromFile($path, $pattern) {
    if (-not (Test-Path $path)) { return @() }
    Select-String -Path $path -Pattern $pattern -AllMatches |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Value }
}

function Extract-DefinitionIds($path, $pattern) {
    if (-not (Test-Path $path)) { return @() }
    Select-String -Path $path -Pattern $pattern -AllMatches |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Groups[1].Value }
}

# REQs and ACs can appear in both PRD and SRS; SRS-F and VT only in SRS.
$foundReqs  = @(Extract-IdsFromFile $prdPath '\bREQ-\d{3}\b') + @(Extract-IdsFromFile $srsPath '\bREQ-\d{3}\b')
$foundAcs   = @(Extract-IdsFromFile $prdPath '\bAC-\d{3}\b')  + @(Extract-IdsFromFile $srsPath '\bAC-\d{3}\b')
$foundSrsFs = @(Extract-IdsFromFile $srsPath '\bSRS-F-\d{3}\b')
$foundVts   = @(Extract-IdsFromFile $srsPath '\bVT-\d{3}\b')

# Definitions are authoritative table rows. Cross-reference tables and linked
# requirement columns intentionally repeat IDs and must not be treated as
# duplicate definitions.
$definedReqs = @(Extract-DefinitionIds $prdPath '^\|\s*(REQ-\d{3})\s*\|')
$definedAcs = @(Extract-DefinitionIds $prdPath '^\|\s*(AC-\d{3})\s*\|')
$definedSrsFs = @(Extract-DefinitionIds $srsPath '^\|\s*(SRS-F-\d{3})\s*\|')
$definedVts = @(Extract-DefinitionIds $srsPath '^\|\s*(VT-\d{3})\s*\|')

# ------------------------------------------------------------------
# 4. Load acceptance manifest
# ------------------------------------------------------------------
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json

# ------------------------------------------------------------------
# 5. Collect IDs and scenario IDs from the manifest
# ------------------------------------------------------------------
$manifestReqs   = @{}
$manifestAcs    = @{}
$manifestSrsFs  = @{}
$manifestVts    = @{}
$scenarioIds    = @{}
$scenarioDuplicates = @{}
$srsfScenarioMap = @{}   # SRS-F-XXX -> $true if covered by >=1 scenario
$vtScenarioMap   = @{}   # VT-XXX   -> $true if covered by >=1 scenario

# Pre-populate coverage maps
$expectedSrsFs | ForEach-Object { $srsfScenarioMap[$_] = $false }
$expectedVts   | ForEach-Object { $vtScenarioMap[$_]   = $false }

foreach ($s in $manifest.scenarios) {
    # Check for duplicate scenario IDs
    if ($scenarioIds.ContainsKey($s.id)) {
        $scenarioDuplicates[$s.id] = $true
    }
    $scenarioIds[$s.id] = $true

    # Collect linked IDs into their sets
    if ($s.linkedReqs)   { foreach ($id in $s.linkedReqs)   { $manifestReqs[$id]   = $true } }
    if ($s.linkedAcs)    { foreach ($id in $s.linkedAcs)    { $manifestAcs[$id]    = $true } }
    if ($s.linkedSrsFs)  { foreach ($id in $s.linkedSrsFs)  { $manifestSrsFs[$id]  = $true } }
    if ($s.linkedVts)    { foreach ($id in $s.linkedVts)    { $manifestVts[$id]    = $true } }

    # Mark SRS-F coverage
    if ($s.linkedSrsFs) {
        foreach ($id in $s.linkedSrsFs) {
            $srsfScenarioMap[$id] = $true
        }
    }

    # Mark VT coverage
    if ($s.linkedVts) {
        foreach ($id in $s.linkedVts) {
            $vtScenarioMap[$id] = $true
        }
    }
}

# ------------------------------------------------------------------
# 6. Validate ID format
#    — every ID found in markdown and every linked ID in the manifest
#      must match the canonical pattern
# ------------------------------------------------------------------
$formatErrors = @()

# Helpers: check a single ID, add to formatErrors if invalid
function Test-CanId ($id, $canonicalSet, $label) {
    if ($id -notin $canonicalSet) {
        $formatErrors += "Invalid ${label} format: $id"
    }
}

$allExpectedSet = @{}; $expectedReqs + $expectedAcs + $expectedSrsFs + $expectedVts | ForEach-Object { $allExpectedSet[$_] = $true }

$foundReqs   | ForEach-Object { Test-CanId $_ $expectedReqs  "REQ" }
$foundAcs    | ForEach-Object { Test-CanId $_ $expectedAcs   "AC" }
$foundSrsFs  | ForEach-Object { Test-CanId $_ $expectedSrsFs "SRS-F" }
$foundVts    | ForEach-Object { Test-CanId $_ $expectedVts   "VT" }

$manifestReqs.Keys   | ForEach-Object { Test-CanId $_ $expectedReqs  "REQ (manifest)" }
$manifestAcs.Keys    | ForEach-Object { Test-CanId $_ $expectedAcs   "AC (manifest)" }
$manifestSrsFs.Keys  | ForEach-Object { Test-CanId $_ $expectedSrsFs "SRS-F (manifest)" }
$manifestVts.Keys    | ForEach-Object { Test-CanId $_ $expectedVts   "VT (manifest)" }

# ------------------------------------------------------------------
# 7. Validate completeness — each expected ID must have exactly one
#    authoritative definition row
# ------------------------------------------------------------------
$completenessErrors = @()

$foundReqSet   = @{}; $definedReqs   | ForEach-Object { $foundReqSet[$_]   = $true }
$foundAcSet    = @{}; $definedAcs    | ForEach-Object { $foundAcSet[$_]    = $true }
$foundSrsfSet  = @{}; $definedSrsFs  | ForEach-Object { $foundSrsfSet[$_]  = $true }
$foundVtSet    = @{}; $definedVts    | ForEach-Object { $foundVtSet[$_]    = $true }

$expectedReqs  | Where-Object { -not $foundReqSet.ContainsKey($_) }  | ForEach-Object { $completenessErrors += "Missing from docs: $_" }
$expectedAcs   | Where-Object { -not $foundAcSet.ContainsKey($_) }   | ForEach-Object { $completenessErrors += "Missing from docs: $_" }
$expectedSrsFs | Where-Object { -not $foundSrsfSet.ContainsKey($_) } | ForEach-Object { $completenessErrors += "Missing from docs: $_" }
$expectedVts   | Where-Object { -not $foundVtSet.ContainsKey($_) }   | ForEach-Object { $completenessErrors += "Missing from docs: $_" }

# Check for duplicate authoritative definition rows, not valid references.
$reqDups   = $definedReqs   | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { "Duplicate REQ definition: $($_.Name) ($($_.Count)x)" }
$acDups    = $definedAcs    | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { "Duplicate AC definition: $($_.Name) ($($_.Count)x)" }
$srsfDups  = $definedSrsFs  | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { "Duplicate SRS-F definition: $($_.Name) ($($_.Count)x)" }
$vtDups    = $definedVts    | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { "Duplicate VT definition: $($_.Name) ($($_.Count)x)" }

# ------------------------------------------------------------------
# 8. Validate coverage: each SRS-F and VT must have >=1 scenario
# ------------------------------------------------------------------
$coverageErrors = @()

$srsfScenarioMap.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object {
    $coverageErrors += "SRS-F without scenario: $($_.Key)"
}

$vtScenarioMap.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object {
    $coverageErrors += "VT without scenario: $($_.Key)"
}

# ------------------------------------------------------------------
# 9. Validate orphan IDs in the manifest — every linked ID must
#    exist in the expected set
# ------------------------------------------------------------------
$orphanErrors = @()

$manifestReqs.Keys   | Where-Object { $_ -notin $expectedReqs }  | ForEach-Object { $orphanErrors += "Orphan REQ in manifest: $_" }
$manifestAcs.Keys    | Where-Object { $_ -notin $expectedAcs }   | ForEach-Object { $orphanErrors += "Orphan AC in manifest: $_" }
$manifestSrsFs.Keys  | Where-Object { $_ -notin $expectedSrsFs } | ForEach-Object { $orphanErrors += "Orphan SRS-F in manifest: $_" }
$manifestVts.Keys    | Where-Object { $_ -notin $expectedVts }   | ForEach-Object { $orphanErrors += "Orphan VT in manifest: $_" }

# ------------------------------------------------------------------
# 10. Assemble final result
# ------------------------------------------------------------------
$allErrors = @() +
    $formatErrors +
    $completenessErrors +
    $reqDups + $acDups + $srsfDups + $vtDups +
    $coverageErrors +
    $orphanErrors

if ($scenarioDuplicates.Count -gt 0) {
    $scenarioDuplicates.Keys | ForEach-Object { $allErrors += "Duplicate scenario ID: $_" }
}

if ($allErrors.Count -eq 0) {
    Write-Host "TRACE PASS: REQ=20 AC=64 SRS-F=20 VT=36"
    exit 0
} else {
    Write-Host "TRACE FAIL:"
    $allErrors | ForEach-Object { Write-Host "  $_" }
    exit 1
}
