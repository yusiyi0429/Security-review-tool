param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [string]$PortablePackage,

    [string]$SigningCertificateThumbprint,

    [switch]$AllowUnsignedPilot,

    [string]$OutputDir = (Join-Path $PSScriptRoot ".." "artifacts" "release"),

    [string]$Configuration = "Release",

    [string]$RuntimeIdentifier = "win-x64",

    [string]$InnoCompiler
)
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot | Split-Path -Parent
$outputDirFull = [System.IO.Path]::GetFullPath($OutputDir)
$tempBase = Join-Path ([System.IO.Path]::GetTempPath()) "SecurityReviewToolInstaller"
$tempRoot = Join-Path $tempBase ([Guid]::NewGuid().ToString("N"))

function Resolve-InnoCompiler([string]$ExplicitPath) {
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Inno Setup compiler not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }

    throw "Inno Setup compiler (ISCC.exe) was not found. Install Inno Setup 6 or 7, or pass -InnoCompiler <path>."
}

function Remove-VerifiedTempDirectory([string]$Path, [string]$BasePath) {
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedBase = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\')
    if (-not $resolvedPath.StartsWith("$resolvedBase\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove temporary directory outside the expected base path: $resolvedPath"
    }

    Remove-Item -LiteralPath $resolvedPath -Recurse -Force
}

Push-Location $root
try {
    $versionFile = Join-Path $root "VERSION"
    if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
        throw "Version file not found: $versionFile"
    }
    $repositoryVersion = (Get-Content -LiteralPath $versionFile -Raw -Encoding UTF8).Trim()
    $allowedVersionPattern = '^' + [regex]::Escape($repositoryVersion) + '(?:[-+][0-9A-Za-z.-]+)?$'
    if ($Version -notmatch $allowedVersionPattern) {
        throw "Requested installer version '$Version' does not match repository version '$repositoryVersion'."
    }

    if ($RuntimeIdentifier -ne "win-x64") {
        throw "The installer currently supports only RuntimeIdentifier win-x64."
    }
    if ($SigningCertificateThumbprint -and $AllowUnsignedPilot) {
        throw "Cannot specify both -SigningCertificateThumbprint and -AllowUnsignedPilot."
    }
    if (-not $SigningCertificateThumbprint -and -not $AllowUnsignedPilot) {
        throw "Either -SigningCertificateThumbprint or -AllowUnsignedPilot is required."
    }

    New-Item -ItemType Directory -Path $outputDirFull -Force | Out-Null

    if (-not $PortablePackage) {
        $PortablePackage = Join-Path $outputDirFull "SecurityReviewTool-$Version-$RuntimeIdentifier.zip"
        if (-not (Test-Path -LiteralPath $PortablePackage -PathType Leaf)) {
            $packageArgs = @{
                Version = $Version
                OutputDir = $outputDirFull
                Configuration = $Configuration
                RuntimeIdentifier = $RuntimeIdentifier
            }
            if ($SigningCertificateThumbprint) {
                $packageArgs.SigningCertificateThumbprint = $SigningCertificateThumbprint
            } else {
                $packageArgs.AllowUnsignedPilot = $true
            }

            & (Join-Path $PSScriptRoot "package.ps1") @packageArgs
        }
    }

    $portablePackageFull = (Resolve-Path -LiteralPath $PortablePackage).Path
    $verifyArgs = @{ Package = $portablePackageFull }
    if ($AllowUnsignedPilot) { $verifyArgs.RequireUnsignedPilotWarning = $true }
    & (Join-Path $PSScriptRoot "verify-package.ps1") @verifyArgs

    $versionMatch = [regex]::Match($Version, '^(\d+)\.(\d+)\.(\d+)')
    $numericVersion = "$($versionMatch.Groups[1].Value).$($versionMatch.Groups[2].Value).$($versionMatch.Groups[3].Value).0"
    $installerName = "SecurityReviewTool-$Version-$RuntimeIdentifier-setup.exe"
    $installerPath = Join-Path $outputDirFull $installerName
    if (Test-Path -LiteralPath $installerPath) {
        throw "Installer already exists at $installerPath. Remove it or bump the version."
    }

    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $stageDir = Join-Path $tempRoot "app"
    Expand-Archive -LiteralPath $portablePackageFull -DestinationPath $stageDir

    $manifestPath = Join-Path $stageDir "release-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.version -ne $Version) {
        throw "Portable package version '$($manifest.version)' does not match requested installer version '$Version'."
    }
    $expectedSignerMode = if ($SigningCertificateThumbprint) { "authenticode" } else { "unsigned_pilot" }
    if ($manifest.signer_mode -ne $expectedSignerMode) {
        throw "Portable package signer mode '$($manifest.signer_mode)' does not match '$expectedSignerMode'."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $stageDir "SecurityReviewTool.exe") -PathType Leaf)) {
        throw "SecurityReviewTool.exe is missing from the verified portable package."
    }

    $compiler = Resolve-InnoCompiler $InnoCompiler
    $installerScript = Join-Path $PSScriptRoot "installer.iss"
    $compileArgs = @(
        "/DAppVersion=$Version",
        "/DNumericVersion=$numericVersion",
        "/DSourceDir=$stageDir",
        "/DOutputDir=$outputDirFull",
        $installerScript
    )

    Write-Host "=== Build SecurityReviewTool installer $Version ==="
    Write-Host "  Source:   $portablePackageFull"
    Write-Host "  Compiler: $compiler"
    & $compiler @compileArgs
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compiler failed with exit code $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        throw "Inno Setup completed but the expected installer was not created: $installerPath"
    }

    if ($SigningCertificateThumbprint) {
        $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
        if (-not $signtool) { throw "signtool.exe was not found in PATH." }

        & $signtool.Source sign `
            /sha1 $SigningCertificateThumbprint `
            /fd SHA256 `
            /tr http://timestamp.digicert.com `
            /td SHA256 `
            $installerPath
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed for $installerPath" }

        $signature = Get-AuthenticodeSignature -LiteralPath $installerPath
        if ($signature.Status -ne "Valid") {
            throw "Installer Authenticode signature is not valid: $($signature.Status)"
        }
    } else {
        Write-Warning "Installer is unsigned and intended only for authorized pilot use."
    }

    $installerHash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$installerHash  $installerName" | Set-Content -LiteralPath "$installerPath.sha256" -Encoding ASCII

    Write-Host ""
    Write-Host "=== Installer complete ==="
    Write-Host "  Setup:  $installerPath"
    Write-Host "  SHA256: $installerHash"
    Write-Host "  Mode:   $expectedSignerMode"
} finally {
    Pop-Location
    Remove-VerifiedTempDirectory -Path $tempRoot -BasePath $tempBase
}
