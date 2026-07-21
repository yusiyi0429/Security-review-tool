param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Package,

    [switch]$RequireUnsignedPilotWarning
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path -Parent
Push-Location $root
try {
    Write-Host "=== Verify package: $Package ==="

    $packagePath = Resolve-Path $Package

    # ------------------------------------------------------------------
    # 1. Extract ZIP to temp directory
    # ------------------------------------------------------------------
    Write-Host "[1/10] Extract ZIP"
    $extractDir = Join-Path ([System.IO.Path]::GetTempPath()) "srt-pkg-verify-$([System.IO.Path]::GetRandomFileName())"
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $extractDir)

    # Check for path traversal (any entry with .. in path)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.Contains("..")) {
                throw "Path traversal detected in ZIP: $($entry.FullName)"
            }
        }
        # Check for duplicate names
        $seen = @{}
        foreach ($entry in $zip.Entries) {
            $lower = $entry.FullName.ToLowerInvariant()
            if ($seen.ContainsKey($lower)) {
                throw "Duplicate/case-colliding ZIP entry: $($entry.FullName)"
            }
            $seen[$lower] = $true
        }
    } finally {
        $zip.Dispose()
    }

    Write-Host "  Extracted to: $extractDir"

    # ------------------------------------------------------------------
    # 2. Compare files against allowlist
    # ------------------------------------------------------------------
    Write-Host "[2/10] Compare against allowlist"

    $allowlistPath = Join-Path $PSScriptRoot "package-file-allowlist.txt"
    $allowlistRaw = Get-Content $allowlistPath | Where-Object {
        $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#")
    } | ForEach-Object { $_.Trim() }

    function Test-MatchesAny($path, $patterns) {
        foreach ($p in $patterns) {
            if ($p -eq $path) { return $true }
            if ($path -like $p) { return $true }
            if ($p.Contains("*")) {
                $regex = "^" + [regex]::Escape($p).Replace("\*", ".*") + "$"
                if ($path -match $regex) { return $true }
            }
            if ($p.EndsWith("/**")) {
                $prefix = $p.Substring(0, $p.Length - 3)
                if ($path.StartsWith($prefix, [StringComparison]::Ordinal)) { return $true }
            }
            if ($p.EndsWith("/*.dll")) {
                $prefix = $p.Substring(0, $p.Length - 6)
                if ($path.StartsWith($prefix, [StringComparison]::Ordinal) -and
                    $path.EndsWith(".dll", [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
            if ($p.EndsWith("/*.json")) {
                $prefix = $p.Substring(0, $p.Length - 7)
                if ($path.StartsWith($prefix, [StringComparison]::Ordinal) -and
                    $path.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
        }
        return $false
    }

    $unallowed = @()
    $extractedFiles = Get-ChildItem -Recurse -File -Path $extractDir | ForEach-Object {
        $normalized = $_.FullName.Substring($extractDir.Length + 1).Replace("\", "/")
        if (-not (Test-MatchesAny $normalized $allowlistRaw)) {
            $unallowed += $normalized
        }
        $normalized
    }

    if ($unallowed.Count -gt 0) {
        $unallowed | ForEach-Object { Write-Host "  UNALLOWED: $_" }
        throw "Found $($unallowed.Count) unallowlisted file(s) in package."
    }
    Write-Host "  All files matched allowlist."

    # ------------------------------------------------------------------
    # 3. Validate release-manifest.json
    # ------------------------------------------------------------------
    Write-Host "[3/10] Validate release-manifest.json"

    $manifestPath = Join-Path $extractDir "release-manifest.json"
    if (-not (Test-Path $manifestPath)) {
        throw "release-manifest.json not found in package."
    }

    $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $manifest) { throw "release-manifest.json is not valid JSON." }

    # Validate required fields
    $requiredFields = @("schema_version", "product", "version", "runtime_version",
        "sdk_version", "target_rid", "created_utc", "signer_mode", "files")
    foreach ($field in $requiredFields) {
        if (-not ($manifest.PSObject.Properties.Name -contains $field)) {
            throw "Missing required field in manifest: $field"
        }
    }

    if ($manifest.schema_version -ne 1) {
        throw "Unsupported manifest schema_version: $($manifest.schema_version)"
    }

    if ($manifest.signer_mode -notin @("authenticode", "unsigned_pilot")) {
        throw "Invalid signer_mode: $($manifest.signer_mode)"
    }

    # Validate manifest files against extracted content
    Write-Host "[4/10] Cross-check manifest files vs extracted content"

    $manifestFiles = @{}
    foreach ($f in $manifest.files) {
        if ($manifestFiles.ContainsKey($f.path)) {
            throw "Duplicate file path in manifest: $($f.path)"
        }
        $manifestFiles[$f.path] = @{ size = $f.size; sha256 = $f.sha256 }
    }

    $actualFiles = @{}
    Get-ChildItem -Recurse -File -Path $extractDir | ForEach-Object {
        $relative = $_.FullName.Substring($extractDir.Length + 1).Replace("\", "/")
        # Exclude release-manifest.schema.json from comparison (reference only)
        if ($relative -eq "release-manifest.schema.json") { return }
        # Exclude manifest itself from file list
        if ($relative -eq "release-manifest.json") {
            $actualFiles[$relative] = @{ size = $_.Length; sha256 = "n/a" }
            return
        }

        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $hashHex = [System.BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()

        $actualFiles[$relative] = @{ size = $_.Length; sha256 = $hashHex }
    }

    # Every manifest file must exist in actual
    foreach ($mf in $manifest.files) {
        if (-not $actualFiles.ContainsKey($mf.path)) {
            throw "Manifest lists '$($mf.path)' but file not found in package."
        }
        $actual = $actualFiles[$mf.path]
        if ($actual.size -ne $mf.size) {
            throw "Size mismatch for '$($mf.path)': manifest=$($mf.size), actual=$($actual.size)"
        }
        if ($actual.sha256 -ne $mf.sha256) {
            throw "SHA-256 mismatch for '$($mf.path)': manifest=$($mf.sha256), actual=$($actual.sha256)"
        }
    }

    # Every actual file (except manifest) must be in manifest
    foreach ($af in $actualFiles.GetEnumerator()) {
        if ($af.Key -eq "release-manifest.json") { continue }
        if (-not $manifestFiles.ContainsKey($af.Key)) {
            throw "File '$($af.Key)' exists in package but not in manifest."
        }
    }

    Write-Host "  $($manifest.files.Count) files cross-checked OK."

    # ------------------------------------------------------------------
    # 5. Validate SBOM
    # ------------------------------------------------------------------
    Write-Host "[5/10] Validate SBOM"

    $sbomPath = Join-Path $extractDir "_manifest/spdx_2.2/manifest.spdx.json"
    if (-not (Test-Path $sbomPath)) {
        throw "SBOM not found at expected path: $sbomPath"
    }

    $sbom = Get-Content $sbomPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $sbom) { throw "SBOM is not valid JSON." }
    Write-Host "  SBOM is valid JSON."

    # ------------------------------------------------------------------
    # 6. Check trusted-signers.json
    # ------------------------------------------------------------------
    Write-Host "[6/10] Check trusted-signers.json"

    $signersPath = Join-Path $extractDir "Assets/rules/trusted-signers.json"
    if (-not (Test-Path $signersPath)) {
        throw "trusted-signers.json not found."
    }
    $signers = Get-Content $signersPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $signers) { throw "trusted-signers.json is not valid JSON." }
    Write-Host "  trusted-signers.json is valid JSON."

    # ------------------------------------------------------------------
    # 7. Forbidden pattern check
    # ------------------------------------------------------------------
    Write-Host "[7/10] Forbidden pattern check"

    $forbiddenExtensions = @(".pdb", ".xml")
    $forbiddenKeywords = @("test", "corpus", "workbook", "keyring",
        "credential", "private", "dump", ".db", ".sqlite", ".sqlite3",
        "wal", "shm", ".git", "config", "temp", "report", "source")

    Get-ChildItem -Recurse -File -Path $extractDir | ForEach-Object {
        $relative = $_.FullName.Substring($extractDir.Length + 1).Replace("\", "/")
        $lower = $relative.ToLowerInvariant()

        # Allow release-manifest.schema.json (it's a reference schema)
        if ($relative -eq "release-manifest.schema.json") { return }

        foreach ($ext in $forbiddenExtensions) {
            if ($relative.EndsWith($ext, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Forbidden file extension in package: $relative"
            }
        }
        foreach ($kw in $forbiddenKeywords) {
            if ($lower.Contains($kw, [StringComparison]::Ordinal)) {
                throw "Forbidden keyword '$kw' in file path: $relative"
            }
        }
    }
    Write-Host "  No forbidden files found."

    # ------------------------------------------------------------------
    # 8. Signer mode verification
    # ------------------------------------------------------------------
    Write-Host "[8/10] Signer mode check"

    $manifestSignerMode = $manifest.signer_mode

    if ($RequireUnsignedPilotWarning -and $manifestSignerMode -ne "unsigned_pilot") {
        throw "Expected unsigned_pilot mode but manifest says $manifestSignerMode"
    }

    if ($manifestSignerMode -eq "unsigned_pilot") {
        Write-Host "  Package is unsigned (pilot mode)."
        Write-Host "  Verify SHA-256 before use: Get-FileHash -Algorithm SHA256 $packagePath"
    } elseif ($manifestSignerMode -eq "authenticode") {
        Write-Host "  Package is signed (authenticode mode)."
        if ($IsWindows) {
            $sigResult = Get-AuthenticodeSignature -FilePath $packagePath
            if ($sigResult.Status -ne "Valid") {
                throw "Authenticode signature is not valid: $($sigResult.Status)"
            }
            Write-Host "  Signature valid: $($sigResult.SignerCertificate.Subject)"
        } else {
            Write-Host "  (Windows-only Authenticode check skipped on non-Windows)"
        }
    }

    # ------------------------------------------------------------------
    # 9. PE architecture check (Windows-only)
    # ------------------------------------------------------------------
    Write-Host "[9/10] PE architecture check"

    if ($IsWindows) {
        $mainExe = Join-Path $extractDir "SecurityReviewTool.exe"
        if (-not (Test-Path $mainExe)) {
            throw "Main executable SecurityReviewTool.exe not found."
        }

        $peBytes = [System.IO.File]::ReadAllBytes($mainExe)
        # PE signature at offset 0x3C
        if ($peBytes.Length -lt 0x40) { throw "File too small for PE header." }
        $peOffset = [System.BitConverter]::ToInt32($peBytes, 0x3C)
        # Machine field is at PE offset + 4
        $machineOffset = $peOffset + 4
        $machine = [System.BitConverter]::ToUInt16($peBytes, $machineOffset)

        # IMAGE_FILE_MACHINE_AMD64 = 0x8664
        if ($machine -ne 0x8664) {
            throw "Main executable is not x64 (machine type: 0x$($machine.ToString('X4')))"
        }
        Write-Host "  PE architecture: x64 (AMD64)"
    } else {
        Write-Host "  (Windows-only PE check skipped on non-Windows)"
    }

    # ------------------------------------------------------------------
    # 10. No writable app-data files
    # ------------------------------------------------------------------
    Write-Host "[10/10] No writable app-data files"

    # Check that no .db, .sqlite, .sqlite3, .wal, .shm, .log, .config files exist
    $statefulExts = @(".db", ".sqlite", ".sqlite3", ".wal", ".shm", ".log", ".config")
    $found = Get-ChildItem -Recurse -File -Path $extractDir | Where-Object {
        $statefulExts -contains $_.Extension.ToLowerInvariant()
    }
    if ($found) {
        $found | ForEach-Object { Write-Host "  STATEFUL: $($_.FullName)" }
        throw "Found $($found.Count) stateful/writable file(s) in package — not allowed."
    }
    Write-Host "  No stateful files detected."

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "=== Package verification PASSED ==="
} catch {
    Write-Host "=== Package verification FAILED ===" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    throw
} finally {
    Pop-Location
}
