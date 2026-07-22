param(
  [ValidateSet("Unit", "Contract", "ParserCorpus", "Integration", "WindowsSecurity", "Performance")]
  [string[]]$Lane = @("Unit", "Contract", "Integration"),
  [string]$RuntimeIdentifier = "win-x64",
  [switch]$RequireWindowsSecurity,
  [switch]$RequireCorpus,
  [switch]$RequirePerformanceHost
)
$ErrorActionPreference = "Stop"
$projects = @{
  Unit = "tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj"
  Contract = "tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj"
  ParserCorpus = "tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj"
  Integration = "tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj"
  WindowsSecurity = "tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj"
  Performance = "tests/SecurityReview.PerformanceTests/SecurityReview.PerformanceTests.csproj"
}
if ($RequireWindowsSecurity -and -not $IsWindows) { throw "WindowsSecurity lane requires Windows." }
if ($RequireWindowsSecurity -and $env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY -ne "1") { throw "SECURITY_REVIEW_RUN_WINDOWS_SECURITY=1 is required so the lane cannot report success from skipped tests." }
if ($RequireCorpus -and -not (Test-Path "tests/Corpus/corpus-manifest.json")) { throw "Corpus manifest is required." }
if ($RequirePerformanceHost -and $env:SECURITY_REVIEW_PERF_HOST -ne "1") { throw "Performance host marker is required." }
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
if ($LASTEXITCODE -ne 0) { throw "Locked restore failed." }
foreach ($name in $Lane) {
  dotnet test $projects[$name] -c Release -r $RuntimeIdentifier --no-restore --logger "trx;LogFileName=$name.trx"
  if ($LASTEXITCODE -ne 0) { throw "$name lane failed." }
}
