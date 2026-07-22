param(
  [ValidateSet("Debug", "Release")][string]$Configuration = "Release",
  [string]$RuntimeIdentifier = "win-x64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  dotnet tool restore
  $restoreArgs = @(
    "restore", "SecurityReviewTool.sln",
    "--locked-mode",
    "-r", $RuntimeIdentifier,
    "--verbosity", "minimal"
  )
  if ($env:SECURITY_REVIEW_NUGET_CONFIG) {
    if (-not (Test-Path -LiteralPath $env:SECURITY_REVIEW_NUGET_CONFIG -PathType Leaf)) { throw "External NuGet config not found." }
    $restoreArgs += @("--configfile", $env:SECURITY_REVIEW_NUGET_CONFIG)
  }
  dotnet @restoreArgs
  # Solution-level build does not accept a RuntimeIdentifier. The RID is
  # applied during restore so each project has the locked win-x64 assets.
  dotnet build SecurityReviewTool.sln -c $Configuration --no-restore
  dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
} finally {
  Pop-Location
}
