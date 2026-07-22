param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$BuildPath,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$OutputPath,

    [string]$NamespaceBase = "https://security-review-tool.invalid/sbom",
    [string]$PackageName = "SecurityReviewTool"
)
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot | Split-Path -Parent
Push-Location $root
try {
    # Restore repo-local tools (sbom-tool)
    dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed." }

    $sbomArgs = @(
        "sbom-tool", "generate",
        "-b", $BuildPath,
        "-bc", ".",
        "-pn", $PackageName,
        "-pv", $Version,
        "-ps", "InternalSecurityEngineering",
        "-nsb", $NamespaceBase
    )

    $manifestDir = Join-Path $OutputPath "_manifest"
    if (-not (Test-Path -LiteralPath $manifestDir -PathType Container)) {
        New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
    }

    $previousRollForward = $env:DOTNET_ROLL_FORWARD
    try {
        # The locked SBOM tool targets .NET 8; permit it to run on a newer build-host runtime.
        $env:DOTNET_ROLL_FORWARD = "Major"
        dotnet tool run @sbomArgs
        if ($LASTEXITCODE -ne 0) { throw "sbom-tool generate failed." }
    } finally {
        if ($null -eq $previousRollForward) {
            Remove-Item Env:\DOTNET_ROLL_FORWARD -ErrorAction SilentlyContinue
        } else {
            $env:DOTNET_ROLL_FORWARD = $previousRollForward
        }
    }

    # Move generated SBOM into the output path if it landed elsewhere
    $generatedManifestDir = Join-Path $BuildPath "_manifest"
    if (Test-Path -LiteralPath $generatedManifestDir -PathType Container) {
        $targetManifestDir = Join-Path $OutputPath "_manifest"
        if ((Resolve-Path $generatedManifestDir).Path -ne (Resolve-Path $targetManifestDir).Path) {
            Copy-Item -Recurse -Force -Path "$generatedManifestDir/*" -Destination $targetManifestDir
            Remove-Item -Recurse -Force $generatedManifestDir
        }
    }

    # Verify SBOM output exists
    $sbomFile = Join-Path $manifestDir "spdx_2.2/manifest.spdx.json"
    if (-not (Test-Path -LiteralPath $sbomFile -PathType Leaf)) {
        throw "SBOM manifest not found at $sbomFile after generation."
    }

    # Validate it is parseable JSON
    $null = Get-Content $sbomFile -Raw -Encoding UTF8 | ConvertFrom-Json

    Write-Host "SBOM generated: $sbomFile"
} finally {
    Pop-Location
}
