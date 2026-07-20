# Security Review P0 Foundation and Windows Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a reproducible .NET solution and prove, on supported Windows, that an AppContainer parser worker has no network/root-directory authority, can read exactly one duplicated handle, and is isolated from crash, timeout, memory exhaustion, and child processes.

**Architecture:** Domain and protocol projects stay platform-neutral. Windows isolation lives behind Application ports in Infrastructure, while a small console worker exercises the same launch path that production parsers will use. The desktop and all later phases are blocked until the fail-closed sandbox self-test passes.

**Tech Stack:** .NET SDK 10.0.302, C# 14, WPF project skeleton, Win32 AppContainer/Job/Named Pipe/DuplicateHandle APIs, xUnit.net v3, PowerShell 7.

## Global Constraints

- Build `win-x64`, self-contained, without installer/service/updater.
- Treat all worker input as hostile; worker receives no network capability and no scan-root path authority.
- IPC frame limit is 1 MiB; parser protocol starts at version 1.
- Sandbox failure is fail-closed in release builds.
- Tests use synthetic canaries and must not log complete paths, file contents, credentials, or pipe payloads.
- Pin SDK/packages and commit lock files; warnings and analyzers fail the build.

---

## Task P0-T1: Bootstrap the reproducible solution

**Files:**
- Create: `global.json`
- Create: `Directory.Build.props`
- Create: `Directory.Packages.props`
- Create: `NuGet.config`
- Create: `.editorconfig`
- Create: `.gitignore`
- Create: `.config/dotnet-tools.json`
- Create: `SecurityReviewTool.sln`
- Create: all `src/*/*.csproj`, `tools/*/*.csproj`, and `tests/*/*.csproj` listed in the master plan
- Create: `build/build.ps1`
- Create: `build/test.ps1`
- Create: `src/SecurityReview.Domain/Identifiers.cs`
- Create: `tests/SecurityReview.UnitTests/Bootstrap/ToolchainTests.cs`
- Create: `tests/SecurityReview.UnitTests/Architecture/ProjectDependencyTests.cs`

**Interfaces:**
- Consumes: the repository layout and package table in the master plan.
- Produces: a buildable solution, central package versions, locked restore, uniform compiler rules, and project boundaries consumed by every later task.

- [ ] **Step 1: Record the exact SDK and global compiler policy**

Create `global.json`:

```json
{
  "sdk": {
    "version": "10.0.302",
    "rollForward": "disable",
    "allowPrerelease": false
  }
}
```

Create `Directory.Build.props`:

```xml
<Project>
  <PropertyGroup>
    <TargetFramework Condition="'$(TargetFramework)' == ''">net10.0</TargetFramework>
    <LangVersion>14.0</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <AnalysisLevel>latest-recommended</AnalysisLevel>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
    <Deterministic>true</Deterministic>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <DebugType>embedded</DebugType>
  </PropertyGroup>
</Project>
```

Expected: `dotnet --version` prints exactly `10.0.302`. If it does not, install that SDK before continuing; do not change `global.json` to match an older machine.

- [ ] **Step 2: Pin runtime, parser, test, and SBOM dependencies**

Create `Directory.Packages.props`:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Microsoft.Data.Sqlite" Version="10.0.10" />
    <PackageVersion Include="System.Security.Cryptography.ProtectedData" Version="10.0.10" />
    <PackageVersion Include="System.Text.Encoding.CodePages" Version="10.0.10" />
    <PackageVersion Include="DocumentFormat.OpenXml" Version="3.5.1" />
    <PackageVersion Include="YamlDotNet" Version="18.1.0" />
    <PackageVersion Include="PdfPig" Version="0.1.14" />
    <PackageVersion Include="xunit.v3" Version="3.2.2" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="3.1.5" />
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="18.8.1" />
    <PackageVersion Include="coverlet.collector" Version="10.0.1" />
  </ItemGroup>
</Project>
```

Create `.config/dotnet-tools.json`:

```json
{
  "version": 1,
  "isRoot": true,
  "tools": {
    "microsoft.sbom.dotnettool": {
      "version": "4.1.5",
      "commands": ["sbom-tool"]
    }
  }
}
```

Create `NuGet.config` with only the approved public source shown below. If the organization requires a private mirror, do **not** commit its endpoint: have the platform team provision an external NuGet config and let build scripts accept its path through `SECURITY_REVIEW_NUGET_CONFIG`, passing `--configfile` without printing the path. A build uses exactly one source policy at a time and never keeps an uncontrolled fallback.

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
  <config>
    <add key="dependencyVersion" value="Lowest" />
  </config>
</configuration>
```

Create `.editorconfig` with `root=true`, UTF-8, LF, final newline, trimmed trailing whitespace, four-space C#/PowerShell indentation, two-space JSON/YAML/XML indentation, sorted `System` usings first, explicit accessibility, file-scoped namespace preference, and build-enforced .NET analyzer severities. Exempt Markdown trailing spaces only where they intentionally create a line break.

Create `.gitignore` with, at minimum:

```gitignore
.vs/
**/bin/
**/obj/
artifacts/
TestResults/
*.trx
coverage.*
.env
.env.*
*.db
*.db-wal
*.db-shm
*.log
*.dmp
*.pfx
*.p12
*.key
*.pem
tests/Corpus/Generated/
tests/Performance/Generated/
local/
```

Do not ignore `packages.lock.json`, the sanitized committed corpus, the public signer JSON, or `rules/templates/security-review-rules-template.xlsx`. Add a test/runtime-generated private signing key only below an ignored temp/artifact directory.

- [ ] **Step 3: Generate solution and projects**

Run exactly from the repository root in PowerShell:

```powershell
dotnet new sln --format sln -n SecurityReviewTool

$libraries = @(
  "SecurityReview.Domain",
  "SecurityReview.Application",
  "SecurityReview.ParserContracts",
  "SecurityReview.Parsers",
  "SecurityReview.RulePack",
  "SecurityReview.Infrastructure"
)
foreach ($name in $libraries) {
  dotnet new classlib -n $name -o "src/$name" -f net10.0
}

dotnet new console -n SecurityReview.Worker -o src/SecurityReview.Worker -f net10.0
dotnet new wpf -n SecurityReview.Desktop -o src/SecurityReview.Desktop -f net10.0
dotnet new console -n SecurityReview.RulePackBuilder -o tools/SecurityReview.RulePackBuilder -f net10.0
dotnet new console -n SecurityReview.CorpusTool -o tools/SecurityReview.CorpusTool -f net10.0

$tests = @(
  "SecurityReview.UnitTests",
  "SecurityReview.ContractTests",
  "SecurityReview.ParserCorpusTests",
  "SecurityReview.IntegrationTests",
  "SecurityReview.WindowsSecurityTests",
  "SecurityReview.PerformanceTests"
)
foreach ($name in $tests) {
  dotnet new classlib -n $name -o "tests/$name" -f net10.0
}

Get-ChildItem src,tools,tests -Filter *.csproj -Recurse |
  ForEach-Object { dotnet sln SecurityReviewTool.sln add $_.FullName }
```

- [ ] **Step 4: Set exact project references and Windows targets**

Run:

```powershell
dotnet add src/SecurityReview.Application reference src/SecurityReview.Domain src/SecurityReview.ParserContracts src/SecurityReview.RulePack
dotnet add src/SecurityReview.ParserContracts reference src/SecurityReview.Domain
dotnet add src/SecurityReview.Parsers reference src/SecurityReview.Domain src/SecurityReview.ParserContracts
dotnet add src/SecurityReview.RulePack reference src/SecurityReview.Domain src/SecurityReview.ParserContracts
dotnet add src/SecurityReview.Infrastructure reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.RulePack
dotnet add src/SecurityReview.Worker reference src/SecurityReview.Domain src/SecurityReview.ParserContracts src/SecurityReview.Parsers
dotnet add src/SecurityReview.Desktop reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.Infrastructure
dotnet add tools/SecurityReview.RulePackBuilder reference src/SecurityReview.Domain src/SecurityReview.RulePack
dotnet add tools/SecurityReview.CorpusTool reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack src/SecurityReview.Infrastructure

dotnet add tests/SecurityReview.UnitTests reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack src/SecurityReview.Infrastructure src/SecurityReview.Desktop
dotnet add tests/SecurityReview.ContractTests reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.RulePack src/SecurityReview.Infrastructure
dotnet add tests/SecurityReview.ParserCorpusTests reference src/SecurityReview.Domain src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack
dotnet add tests/SecurityReview.IntegrationTests reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack src/SecurityReview.Infrastructure src/SecurityReview.Desktop
dotnet add tests/SecurityReview.WindowsSecurityTests reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack src/SecurityReview.Infrastructure src/SecurityReview.Worker
dotnet add tests/SecurityReview.PerformanceTests reference src/SecurityReview.Domain src/SecurityReview.Application src/SecurityReview.ParserContracts src/SecurityReview.Parsers src/SecurityReview.RulePack src/SecurityReview.Infrastructure src/SecurityReview.Worker

dotnet add src/SecurityReview.Infrastructure package Microsoft.Data.Sqlite
dotnet add src/SecurityReview.Infrastructure package System.Security.Cryptography.ProtectedData
dotnet add src/SecurityReview.Worker package System.Text.Encoding.CodePages
dotnet add src/SecurityReview.Parsers package DocumentFormat.OpenXml
dotnet add src/SecurityReview.Parsers package YamlDotNet
dotnet add src/SecurityReview.Parsers package PdfPig
dotnet add tools/SecurityReview.RulePackBuilder package DocumentFormat.OpenXml
```

Set `TargetFramework` to `net10.0-windows10.0.19041.0`, `RuntimeIdentifier` to `win-x64`, and `EnableWindowsTargeting` to `true` in Infrastructure, Worker, Desktop, CorpusTool, and **all six test projects**. This is intentional: the product and CI acceptance target Windows only, several contract/unit tests exercise DPAPI, Win32 path semantics, and WPF view models, and a `net10.0` project cannot reference the Windows-targeted Infrastructure project. Desktop keeps `UseWPF=true`, `OutputType=WinExe`, and sets `AssemblyName=SecurityReviewTool`; Worker keeps `OutputType=Exe` and `AssemblyName=SecurityReview.Worker`; CorpusTool keeps `OutputType=Exe`. Domain, Application, ParserContracts, Parsers, RulePack, and RulePackBuilder remain `net10.0`. Remove generated `Class1.cs` from all library/test projects. Add this to every test project:

```xml
<PropertyGroup>
  <IsTestProject>true</IsTestProject>
  <IsPackable>false</IsPackable>
</PropertyGroup>
<ItemGroup>
  <Using Include="Xunit" />
  <PackageReference Include="xunit.v3" />
  <PackageReference Include="xunit.runner.visualstudio" PrivateAssets="all" />
  <PackageReference Include="Microsoft.NET.Test.Sdk" PrivateAssets="all" />
  <PackageReference Include="coverlet.collector" PrivateAssets="all" />
</ItemGroup>
```

Run `dotnet list SecurityReviewTool.sln reference` and verify the graph matches the commands above. `SecurityReview.Domain` must have zero project references; ParserContracts may reference only Domain; Parsers and RulePack may reference only Domain and ParserContracts; neither Domain nor ParserContracts may reference Infrastructure, Desktop, or Worker; Desktop must not reference Worker directly.

- [ ] **Step 5: Write the first toolchain and architecture tests**

Create `tests/SecurityReview.UnitTests/Bootstrap/ToolchainTests.cs`:

```csharp
namespace SecurityReview.UnitTests.Bootstrap;

public sealed class ToolchainTests
{
    [Fact]
    public void Runtime_major_is_ten() => Assert.Equal(10, Environment.Version.Major);
}
```

Create `tests/SecurityReview.UnitTests/Architecture/ProjectDependencyTests.cs`:

```csharp
using SecurityReview.Domain;

namespace SecurityReview.UnitTests.Architecture;

public sealed class ProjectDependencyTests
{
    [Fact]
    public void Domain_has_no_infrastructure_or_ui_reference()
    {
        string[] forbidden = ["SecurityReview.Infrastructure", "SecurityReview.Desktop", "PresentationFramework"];
        string[] references = typeof(ScanId).Assembly.GetReferencedAssemblies().Select(x => x.Name ?? "").ToArray();
        Assert.DoesNotContain(references, name => forbidden.Contains(name, StringComparer.Ordinal));
    }
}
```

Add `src/SecurityReview.Domain/Identifiers.cs` with the identifiers used across plan boundaries:

```csharp
namespace SecurityReview.Domain;

public readonly record struct ScanId(Guid Value);
public readonly record struct FileId(Guid Value);
public readonly record struct JobId(Guid Value);
public readonly record struct CandidateId(Guid Value);
public readonly record struct FindingGroupId(Guid Value);
public readonly record struct FindingOccurrenceId(Guid Value);
public readonly record struct RuleId(string Value);
public readonly record struct DetectorId(string Value);
```

- [ ] **Step 6: Add deterministic build/test scripts**

Create `build/build.ps1`:

```powershell
param([ValidateSet("Debug", "Release")][string]$Configuration = "Release")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  dotnet tool restore
  $restoreArgs = @("restore", "SecurityReviewTool.sln", "--locked-mode", "--verbosity", "minimal")
  if ($env:SECURITY_REVIEW_NUGET_CONFIG) {
    if (-not (Test-Path -LiteralPath $env:SECURITY_REVIEW_NUGET_CONFIG -PathType Leaf)) { throw "External NuGet config not found." }
    $restoreArgs += @("--configfile", $env:SECURITY_REVIEW_NUGET_CONFIG)
  }
  dotnet @restoreArgs
  dotnet build SecurityReviewTool.sln -c $Configuration --no-restore
  dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
} finally {
  Pop-Location
}
```

Create `build/test.ps1` with explicit lanes:

```powershell
param(
  [ValidateSet("Unit", "Contract", "ParserCorpus", "Integration", "WindowsSecurity", "Performance")]
  [string[]]$Lane = @("Unit", "Contract", "Integration"),
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
if ($RequireCorpus -and -not (Test-Path "tests/Corpus/corpus-manifest.json")) { throw "Corpus manifest is required." }
if ($RequirePerformanceHost -and $env:SECURITY_REVIEW_PERF_HOST -ne "1") { throw "Performance host marker is required." }
$restoreArgs = @("restore", "SecurityReviewTool.sln", "--locked-mode", "--verbosity", "minimal")
if ($env:SECURITY_REVIEW_NUGET_CONFIG) {
  if (-not (Test-Path -LiteralPath $env:SECURITY_REVIEW_NUGET_CONFIG -PathType Leaf)) { throw "External NuGet config not found." }
  $restoreArgs += @("--configfile", $env:SECURITY_REVIEW_NUGET_CONFIG)
}
dotnet @restoreArgs
if ($LASTEXITCODE -ne 0) { throw "Locked restore failed." }
foreach ($name in $Lane) {
  dotnet test $projects[$name] -c Release --no-restore --logger "trx;LogFileName=$name.trx"
  if ($LASTEXITCODE -ne 0) { throw "$name lane failed." }
}
```

- [ ] **Step 7: Restore, build, test, inspect locks, and commit**

Use the existing organization repository when one is supplied. If this directory is still outside Git, obtain the project owner's repository/visibility decision, then initialize the approved repository before the first commit; do not infer that the source workbook is safe to commit. The commands below assume Git is initialized and identity/remote policy is already configured.

Run:

```powershell
$restoreArgs = @("restore", "SecurityReviewTool.sln", "--verbosity", "minimal")
if ($env:SECURITY_REVIEW_NUGET_CONFIG) { $restoreArgs += @("--configfile", $env:SECURITY_REVIEW_NUGET_CONFIG) }
dotnet @restoreArgs
dotnet build SecurityReviewTool.sln -c Release --no-restore
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --no-build
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
Get-ChildItem -Recurse -Filter packages.lock.json | Measure-Object
git diff --check
```

Expected: all commands exit 0; at least one `packages.lock.json` exists for every project with a package reference; the two tests pass.

Commit:

```powershell
git add global.json Directory.Build.props Directory.Packages.props NuGet.config .editorconfig .gitignore .config SecurityReviewTool.sln src tools tests build docs/prd docs/srs docs/adr docs/superpowers/plans
git commit -m "build: bootstrap reproducible security review solution"
```

Before committing, run `git status --short` and confirm the root source workbook, Office lock files, local LLM/NuGet configuration, generated artifacts, credentials, and private endpoints are not staged.

## Task P0-T2: Implement scan state and coverage domain

**Files:**
- Create: `src/SecurityReview.Domain/Scans/ScanStatus.cs`
- Create: `src/SecurityReview.Domain/Scans/ScanStateMachine.cs`
- Create: `src/SecurityReview.Domain/Scans/ScanRun.cs`
- Create: `src/SecurityReview.Domain/Scans/CoverageStatus.cs`
- Create: `src/SecurityReview.Domain/Scans/GapReason.cs`
- Create: `src/SecurityReview.Domain/Scans/CoverageGap.cs`
- Create: `src/SecurityReview.Domain/Scans/CoverageSummary.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/ScanStateMachineTests.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/CoverageSummaryTests.cs`

**Interfaces:**
- Consumes: `ScanId` from P0-T1.
- Produces: `ScanStatus`, `ScanStateMachine`, `ScanRun`, `GapReason`, `CoverageGap`, and `CoverageSummary` consumed by orchestration, persistence, UI, and reporting.

- [ ] **Step 1: Write failing transition tests**

Create `ScanStateMachineTests.cs`:

```csharp
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanStateMachineTests
{
    [Theory]
    [InlineData(ScanStatus.Draft, ScanStatus.Preflight)]
    [InlineData(ScanStatus.Preflight, ScanStatus.Running)]
    [InlineData(ScanStatus.Preflight, ScanStatus.Failed)]
    [InlineData(ScanStatus.Running, ScanStatus.Cancelling)]
    [InlineData(ScanStatus.Running, ScanStatus.Completed)]
    [InlineData(ScanStatus.Running, ScanStatus.Partial)]
    [InlineData(ScanStatus.Running, ScanStatus.Failed)]
    [InlineData(ScanStatus.Cancelling, ScanStatus.Cancelled)]
    public void Allows_declared_transition(ScanStatus current, ScanStatus next) =>
        Assert.True(ScanStateMachine.CanTransition(current, next));

    [Theory]
    [InlineData(ScanStatus.Draft, ScanStatus.Completed)]
    [InlineData(ScanStatus.Completed, ScanStatus.Running)]
    [InlineData(ScanStatus.Partial, ScanStatus.Completed)]
    [InlineData(ScanStatus.Cancelled, ScanStatus.Running)]
    public void Rejects_undeclared_transition(ScanStatus current, ScanStatus next) =>
        Assert.False(ScanStateMachine.CanTransition(current, next));

    [Theory]
    [InlineData(ScanStatus.Preflight)]
    [InlineData(ScanStatus.Running)]
    [InlineData(ScanStatus.Cancelling)]
    public void Recovery_maps_non_terminal_work_to_interrupted(ScanStatus status) =>
        Assert.Equal(ScanStatus.Interrupted, ScanStateMachine.RecoverAfterProcessExit(status));
}
```

- [ ] **Step 2: Run the tests and observe the expected compile failure**

Run:

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~ScanStateMachineTests
```

Expected: FAIL because `SecurityReview.Domain.Scans.ScanStatus` and `ScanStateMachine` do not exist.

- [ ] **Step 3: Implement the closed state machine**

Create `ScanStatus.cs` and `ScanStateMachine.cs`:

```csharp
namespace SecurityReview.Domain.Scans;

public enum ScanStatus
{
    Draft, Preflight, Running, Cancelling, Completed, Partial, Cancelled, Failed, Interrupted
}

public static class ScanStateMachine
{
    private static readonly IReadOnlyDictionary<ScanStatus, IReadOnlySet<ScanStatus>> Allowed =
        new Dictionary<ScanStatus, IReadOnlySet<ScanStatus>>
        {
            [ScanStatus.Draft] = new HashSet<ScanStatus> { ScanStatus.Preflight },
            [ScanStatus.Preflight] = new HashSet<ScanStatus> { ScanStatus.Running, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Running] = new HashSet<ScanStatus> { ScanStatus.Cancelling, ScanStatus.Completed, ScanStatus.Partial, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Cancelling] = new HashSet<ScanStatus> { ScanStatus.Cancelled, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Completed] = new HashSet<ScanStatus>(),
            [ScanStatus.Partial] = new HashSet<ScanStatus>(),
            [ScanStatus.Cancelled] = new HashSet<ScanStatus>(),
            [ScanStatus.Failed] = new HashSet<ScanStatus>(),
            [ScanStatus.Interrupted] = new HashSet<ScanStatus>()
        };

    public static bool CanTransition(ScanStatus current, ScanStatus next) => Allowed[current].Contains(next);

    public static ScanStatus RecoverAfterProcessExit(ScanStatus current) => current switch
    {
        ScanStatus.Preflight or ScanStatus.Running or ScanStatus.Cancelling => ScanStatus.Interrupted,
        _ => current
    };
}
```

- [ ] **Step 4: Write failing coverage/conclusion tests**

Create `CoverageSummaryTests.cs`:

```csharp
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class CoverageSummaryTests
{
    [Fact]
    public void All_planned_units_covered_can_complete()
    {
        var summary = CoverageSummary.Create(plannedUnits: 3, coveredUnits: 3, gaps: []);
        Assert.Equal(CoverageStatus.Covered, summary.Status);
        Assert.Equal(ScanStatus.Completed, summary.FinalScanStatus(unresolvedSemanticCandidates: 0));
    }

    [Fact]
    public void Any_gap_forces_partial()
    {
        var gap = CoverageGap.CreateForTest(GapReason.ParserTimeout);
        var summary = CoverageSummary.Create(3, 2, [gap]);
        Assert.Equal(CoverageStatus.PartiallyCovered, summary.Status);
        Assert.Equal(ScanStatus.Partial, summary.FinalScanStatus(0));
    }

    [Fact]
    public void Unresolved_semantic_candidate_forces_partial()
    {
        var summary = CoverageSummary.Create(1, 1, []);
        Assert.Equal(ScanStatus.Partial, summary.FinalScanStatus(1));
    }
}
```

- [ ] **Step 5: Implement coverage values and bounded finalization**

Create the domain types with these exact public shapes:

```csharp
namespace SecurityReview.Domain.Scans;

public enum CoverageStatus { Covered, PartiallyCovered, NotCovered }

public enum GapReason
{
    UnsupportedFormat, UnsupportedRegion, AccessDenied, Encrypted, DecodeUnreliable,
    Corrupt, ArchiveLimit, ParserTimeout, ParserMemory, ParserCrash, SandboxUnavailable,
    FileUnstable, UserExcluded, LlmUnresolved, Cancelled, DiskFull, UnexpectedGitMetadata,
    ParserProtocolMismatch
}

public sealed record CoverageGap(
    Guid GapId, ScanId ScanId, FileId? FileId, string VirtualPath, string FormatId,
    string Stage, GapReason Reason, string DetailCode, long? PlannedBytes,
    long? ProcessedBytes, DateTimeOffset CreatedAtUtc)
{
    public static CoverageGap CreateForTest(GapReason reason) =>
        new(Guid.NewGuid(), new ScanId(Guid.Empty), null, "synthetic", "test", "test",
            reason, "synthetic", 1, 0, DateTimeOffset.UnixEpoch);
}

public sealed record CoverageSummary(int PlannedUnits, int CoveredUnits,
    IReadOnlyList<CoverageGap> Gaps, CoverageStatus Status)
{
    public static CoverageSummary Create(int plannedUnits, int coveredUnits, IReadOnlyList<CoverageGap> gaps)
    {
        if (plannedUnits < 0 || coveredUnits < 0 || coveredUnits > plannedUnits)
            throw new ArgumentOutOfRangeException(nameof(coveredUnits));
        CoverageStatus status = gaps.Count == 0 && coveredUnits == plannedUnits
            ? CoverageStatus.Covered
            : coveredUnits == 0 ? CoverageStatus.NotCovered : CoverageStatus.PartiallyCovered;
        return new(plannedUnits, coveredUnits, gaps, status);
    }

    public ScanStatus FinalScanStatus(int unresolvedSemanticCandidates) =>
        Status == CoverageStatus.Covered && unresolvedSemanticCandidates == 0
            ? ScanStatus.Completed
            : ScanStatus.Partial;
}
```

Create `ScanRun` as an immutable record containing `ScanId`, `Status`, creation/update timestamps, rule/client/pipeline fingerprints, planned count, and optimistic `Version`. Expose `TransitionTo(next, atUtc)` and throw `InvalidOperationException` when `ScanStateMachine.CanTransition` is false.

- [ ] **Step 6: Run focused and project tests, then commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Scans
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
git add src/SecurityReview.Domain/Scans tests/SecurityReview.UnitTests/Scans
git commit -m "feat: define scan state and coverage domain"
```

Expected: all scan and coverage tests pass; no terminal state can return to Running.

## Task P0-T3: Implement the versioned parser IPC contract

**Files:**
- Create: `src/SecurityReview.ParserContracts/Protocol/ProtocolConstants.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/ProtocolEnvelope.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/MessageType.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/ProtocolJsonContext.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/LengthPrefixedJsonProtocol.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/ProtocolException.cs`
- Create: `src/SecurityReview.ParserContracts/Protocol/ProtocolSessionValidator.cs`
- Create: `src/SecurityReview.ParserContracts/Parsing/ParseJob.cs`
- Create: `src/SecurityReview.ParserContracts/Parsing/ParseLimits.cs`
- Create: `src/SecurityReview.ParserContracts/Parsing/ContentChunk.cs`
- Create: `src/SecurityReview.Domain/Findings/SourceLocator.cs`
- Create: `tests/SecurityReview.ContractTests/Protocol/LengthPrefixedJsonProtocolTests.cs`
- Create: `tests/SecurityReview.ContractTests/Protocol/ProtocolValidationTests.cs`

**Interfaces:**
- Consumes: `JobId`, `ScanId`, and `GapReason` domain values.
- Produces: protocol version 1 DTOs and `LengthPrefixedJsonProtocol.ReadAsync/WriteAsync`, used by the worker and trusted coordinator.

- [ ] **Step 1: Write frame round-trip, limit, and truncation tests**

```csharp
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.ContractTests.Protocol;

public sealed class LengthPrefixedJsonProtocolTests
{
    [Fact]
    public async Task Round_trips_a_valid_envelope()
    {
        var expected = ProtocolEnvelope.Create(MessageType.Heartbeat, Guid.Parse("11111111-1111-1111-1111-111111111111"), "{}");
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, CancellationToken.None);
        stream.Position = 0;
        ProtocolEnvelope actual = await LengthPrefixedJsonProtocol.ReadAsync(stream, CancellationToken.None);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task Rejects_frame_larger_than_one_mebibyte()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(BitConverter.GetBytes(ProtocolConstants.MaxFrameBytes + 1));
        stream.Position = 0;
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Rejects_truncated_payload()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(BitConverter.GetBytes(12));
        await stream.WriteAsync("{}"u8.ToArray());
        stream.Position = 0;
        await Assert.ThrowsAsync<EndOfStreamException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, CancellationToken.None));
    }
}
```

- [ ] **Step 2: Run the tests and observe missing contract types**

```powershell
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~LengthPrefixedJsonProtocolTests
```

Expected: FAIL at compile time because the protocol types do not exist.

- [ ] **Step 3: Implement the length-prefixed codec**

```csharp
using System.Buffers.Binary;
using System.Text.Json;

namespace SecurityReview.ParserContracts.Protocol;

public static class ProtocolConstants
{
    public const int Version = 1;
    public const int MaxFrameBytes = 1_048_576;
}

public enum MessageType { Hello, HelloAccepted, ParseJob, ContentChunk, GapProduced, ParseCompleted, ParseFailed, CancelJob, Heartbeat }

public sealed record ProtocolEnvelope(int ProtocolVersion, MessageType MessageType,
    Guid CorrelationId, ScanId? ScanId, JobId? JobId, long Sequence,
    DateTimeOffset SentAtUtc, string PayloadJson)
{
    public static ProtocolEnvelope Create(MessageType type, Guid correlationId, string payloadJson,
        ScanId? scanId = null, JobId? jobId = null) =>
        new(ProtocolConstants.Version, type, correlationId, scanId, jobId, 0,
            DateTimeOffset.UnixEpoch, payloadJson);
}

public sealed class ProtocolException(string message) : Exception(message);

public static class LengthPrefixedJsonProtocol
{
    public static async Task WriteAsync(Stream stream, ProtocolEnvelope message, CancellationToken cancellationToken)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(message, ProtocolJsonContext.Default.ProtocolEnvelope);
        if (payload.Length > ProtocolConstants.MaxFrameBytes) throw new ProtocolException("Frame exceeds the protocol limit.");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static async Task<ProtocolEnvelope> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > ProtocolConstants.MaxFrameBytes) throw new ProtocolException("Invalid frame length.");
        byte[] payload = GC.AllocateUninitializedArray<byte>(length);
        await stream.ReadExactlyAsync(payload, cancellationToken);
        ProtocolEnvelope message = JsonSerializer.Deserialize(payload, ProtocolJsonContext.Default.ProtocolEnvelope)
            ?? throw new ProtocolException("Frame JSON is null.");
        if (message.ProtocolVersion != ProtocolConstants.Version) throw new ProtocolException("Protocol version mismatch.");
        return message;
    }
}
```

Implement `ProtocolJsonContext` in this same step with source generation, camel-case names, maximum depth 32, case-sensitive properties, and `JsonUnmappedMemberHandling.Disallow`. Add a contract test with an unknown member and assert it is rejected; reflection serialization is not permitted in the worker protocol.

- [ ] **Step 4: Define parse DTOs and validation tests**

Create `ProtocolValidationTests.cs` to assert: deadline must be in the future; depth is 0–5; remaining entries is 0–100,000; expanded bytes is 0–50 GiB; frame bytes is 1–1,048,576; a fully serialized `ContentChunk` envelope (including JSON escaping, metadata, and location map) is at most 1 MiB; sequence is non-negative; source ranges never overflow declared length; location-map entries are at most 8,192 and sorted/non-overlapping; canonical locator display is at most 4,096 UTF-16 code units; virtual paths are at most 4,096 UTF-16 code units, relative, well-formed Unicode, and contain no NUL, drive prefix, leading slash, or `..` segment. Include worst-case control characters, Chinese text, backslashes/quotes, and maximum locator metadata—not just plain ASCII.

Use this exact limits record:

```csharp
public sealed record ParseLimits(DateTimeOffset DeadlineUtc, int MaxDepth,
    int MaxEntriesRemaining, long MaxExpandedBytesRemaining, int MaxChunkBytes)
{
    public IReadOnlyList<string> Validate(DateTimeOffset nowUtc)
    {
        var errors = new List<string>();
        if (DeadlineUtc <= nowUtc) errors.Add("deadline_expired");
        if (MaxDepth is < 0 or > 5) errors.Add("depth_out_of_range");
        if (MaxEntriesRemaining is < 0 or > 100_000) errors.Add("entries_out_of_range");
        if (MaxExpandedBytesRemaining is < 0 or > 53_687_091_200L) errors.Add("expanded_bytes_out_of_range");
        if (MaxChunkBytes is < 1 or > 1_048_576) errors.Add("chunk_bytes_out_of_range");
        return errors;
    }
}
```

Define `SourceLocator` in `SecurityReview.Domain.Findings` as a discriminated record family: `PathLocator(pathKind,segmentOrStreamName)`, `TextLocator(line,column,byteStart,byteLength)`, `CellLocator(sheet,cell)`, `JsonLocator(pointer,byteStart,byteLength)`, `NestedLocator(virtualPath,inner)`, `BinaryLocator(section,byteOffset,byteLength)`, `PdfLocator(page,blockIndex)`, and `OciLocator(manifestDigest,layerDigest,layerIndex,internalPath,entryOffset)`. Keeping the locator in Domain lets findings, persistence, reporting, and parser DTOs share it without creating a forbidden Domain → ParserContracts reference.

- [ ] **Step 5: Add handshake and sequence validator**

Create a stateful `ProtocolSessionValidator` that accepts `Hello` sequence 0 once, requires matching 32-byte nonce and worker build SHA-256, then tracks the last sequence and SHA-256 of the canonical frame. The exact same sequence+digest returns `IgnoreDuplicate`; the same sequence with different bytes, a skipped/negative sequence, pre-handshake job message, wrong nonce/build, or message after completion returns `TerminateJob`. `ParseJob`, chunk, gap, completion, failure, and cancel messages require matching non-null `ScanId`/`JobId`; Hello/HelloAccepted require both null; idle heartbeat may omit both and an active heartbeat must include both. Tests cover every branch.

- [ ] **Step 6: Run contract tests and commit**

```powershell
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
git add src/SecurityReview.Domain/Findings/SourceLocator.cs src/SecurityReview.ParserContracts tests/SecurityReview.ContractTests/Protocol
git commit -m "feat: define bounded parser IPC protocol"
```

Expected: all round-trip and rejection tests pass; fuzzing a random 0–2 MiB byte array never allocates over the frame limit or hangs.

## Task P0-T4: Prove AppContainer, Job Object, handle, and pipe isolation

**Files:**
- Create: `src/SecurityReview.Application/Abstractions/IWorkerLauncher.cs`
- Create: `src/SecurityReview.Application/Abstractions/IFileHandleBroker.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Native/NativeMethods.AppContainer.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Native/NativeMethods.Process.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Native/NativeMethods.Job.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Native/NativeMethods.Handle.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/AppContainerProfile.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/WorkerJob.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/WorkerJobSet.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/RestrictedPipeFactory.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/WindowsFileHandleBroker.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/AppContainerWorkerLauncher.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/SandboxLaunchOptions.cs`
- Create: `src/SecurityReview.Worker/Program.cs`
- Create: `src/SecurityReview.Worker/Probe/ProbeCommand.cs`
- Create: `src/SecurityReview.Worker/Probe/ProbeRunner.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Sandbox/AppContainerBoundaryTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Sandbox/JobObjectTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Sandbox/PipeAndHandleTests.cs`

**Interfaces:**
- Consumes: P0-T3 frame protocol.
- Produces: `IWorkerLauncher.LaunchAsync`, `IFileHandleBroker.DuplicateReadOnlyAsync`, `SandboxedWorkerProcess`, and Windows security evidence consumed by P0-T5/P1.

- [ ] **Step 1: Write Windows-only boundary tests before the launcher**

Use a test fixture that creates a temporary root with `allowed.txt` and a sibling `forbidden.txt`, starts local TCP listeners on loopback and the host LAN address, and launches the probe worker. Add assertions:

```csharp
[Fact]
public async Task Worker_reads_duplicated_handle_but_not_sibling_path()
{
    SandboxProbeResult result = await _fixture.RunAsync(ProbeScenario.HandleAndSiblingRead);
    Assert.Equal("CANARY_ALLOWED", result.HandleText);
    Assert.Equal(ProbeAccess.Denied, result.SiblingRead);
}

[Fact]
public async Task Worker_cannot_connect_to_loopback_lan_dns_or_internet()
{
    SandboxProbeResult result = await _fixture.RunAsync(ProbeScenario.NetworkMatrix);
    Assert.All(result.NetworkAttempts, attempt => Assert.Equal(ProbeAccess.Denied, attempt.Access));
}

[Fact]
public async Task Worker_token_contains_expected_appcontainer_sid_and_no_network_capability()
{
    SandboxProbeResult result = await _fixture.RunAsync(ProbeScenario.TokenInspection);
    Assert.True(result.IsAppContainer);
    Assert.Equal(_fixture.ExpectedAppContainerSid, result.AppContainerSid);
    Assert.Empty(result.NetworkCapabilities);
}
```

Guard the fixture with `OperatingSystem.IsWindows()` and an explicit environment variable `SECURITY_REVIEW_RUN_WINDOWS_SECURITY=1`. Release validation sets the variable; a missing variable fails `build/test.ps1 -RequireWindowsSecurity` rather than reporting success from skipped tests.

- [ ] **Step 2: Run the boundary tests and observe missing implementations**

```powershell
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~Sandbox
```

Expected: FAIL because AppContainer/profile/launcher types do not exist.

- [ ] **Step 3: Add source-generated Win32 imports with SafeHandle ownership**

Use `LibraryImport` with `SetLastError=true`; no raw process/job/token/file handle may escape Infrastructure. Required native APIs:

```csharp
[LibraryImport("userenv.dll", EntryPoint = "CreateAppContainerProfile", StringMarshalling = StringMarshalling.Utf16)]
internal static partial int CreateAppContainerProfile(string name, string displayName, string description,
    nint capabilities, uint capabilityCount, out nint appContainerSid);

[LibraryImport("userenv.dll", EntryPoint = "DeriveAppContainerSidFromAppContainerName", StringMarshalling = StringMarshalling.Utf16)]
internal static partial int DeriveAppContainerSidFromAppContainerName(string name, out nint appContainerSid);

[LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateJobObjectW", StringMarshalling = StringMarshalling.Utf16)]
internal static partial SafeJobHandle CreateJobObject(nint jobAttributes, string? name);

[LibraryImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool SetInformationJobObject(SafeJobHandle job, JobObjectInfoClass infoClass,
    nint info, uint infoLength);

[LibraryImport("kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
internal static partial bool DuplicateHandle(SafeProcessHandle sourceProcess, SafeHandle sourceHandle,
    SafeProcessHandle targetProcess, out SafeFileHandle targetHandle, uint desiredAccess,
    [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);
```

Also import `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`, `CreateProcessW`, `AssignProcessToJobObject`, `ResumeThread`, `TerminateJobObject`, `CreateNamedPipeW`, `ConnectNamedPipe`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `OpenProcessToken`, `GetTokenInformation`, `ConvertSidToStringSidW`, and `LocalFree`. Wrap every allocation in `SafeHandle` or `try/finally`; convert non-success HRESULT/Win32 values to a typed `WindowsSecurityException` containing only API name and numeric error code.

- [ ] **Step 4: Implement profile, pipe ACL, job limits, and suspended launch**

Use a stable per-user profile name `Company.SecurityReviewTool.Parser.V1`. `AppContainerProfile.EnsureAsync` first derives the SID, creates only on not-found, grants read/execute to a SHA-256-verified worker staging directory, and returns the SID string. It never grants the SID access to the scan root or `%LOCALAPPDATA%\SecurityReviewTool\data`.

Use nested Jobs so the pool has a real 1 GiB aggregate ceiling while each worker still cannot spawn a child. `WorkerJobSet` owns one scan Job and one child Job per worker:

```csharp
public static ScanJobLimits ScanDefault => new(
    ActiveProcessLimit: 4,
    JobMemoryBytes: 1_073_741_824,
    KillOnJobClose: true);

public static WorkerJobLimits OrdinaryWorker => new(
    ActiveProcessLimit: 1,
    ProcessMemoryBytes: 402_653_184,
    KillOnJobClose: true,
    DieOnUnhandledException: true);

public static WorkerJobLimits OciExclusiveWorker => OrdinaryWorker with
{
    ProcessMemoryBytes = 1_073_741_824
};
```

Assign each worker to both the scan-wide Job and its own active-process-1 child Job; target Windows tests must prove nested limits apply. OCI/Docker top-level work drains ordinary scheduling and runs in one exclusive worker with the OCI limit, still inside the same 1 GiB scan Job. If nested Job assignment is unavailable on a claimed Windows build, sandbox preflight fails closed and M0 cannot pass.

`RestrictedPipeFactory` builds an SDDL DACL containing only the current user SID and exact AppContainer SID, creates the pipe with native `CreateNamedPipeW`, wraps the resulting `SafePipeHandle`, and exposes a `NamedPipeServerStream`. It uses a cryptographically random 128-bit name, byte mode, one server instance, asynchronous I/O, and 1 MiB input/output buffers. No broad `Authenticated Users`, `Users`, `Everyone`, or all-AppPackages ACE is allowed.

`AppContainerWorkerLauncher.LaunchAsync` performs this order exactly: verify staged worker manifest; create pipe; build `SECURITY_CAPABILITIES` with zero capabilities; create worker suspended with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; assign it to the Job; duplicate the input handle; resume; validate Hello nonce/build/SID; return `SandboxedWorkerProcess`. Any error terminates the Job and disposes all handles.

- [ ] **Step 5: Implement probe-only worker commands**

`ProbeRunner` accepts commands only when the worker build defines `SECURITY_REVIEW_SANDBOX_PROBE`. The production worker has no path-based probe command. Scenarios return bounded JSON fields for:

- reading the numeric duplicated handle;
- attempting a sibling path supplied only to the probe build;
- connecting to loopback TCP, host LAN TCP, DNS UDP/53, and a documentation-only external IP;
- inspecting `TokenIsAppContainer`, AppContainer SID, and capabilities;
- spawning a child;
- allocating 512 MiB;
- hanging past deadline;
- terminating with a non-zero exit.

Do not return file content beyond fixed canary labels or raw exception messages.

- [ ] **Step 6: Add Job, pipe, handle, spoof, and lifecycle assertions**

Tests must prove:

1. per-worker active-process limit denies the child or the child Job terminates it, while the scan Job still permits the configured worker pool;
2. 512 MiB allocation terminates an ordinary worker and reports `ParserMemory`; OCI-exclusive tests prove the 1 GiB ceiling without exceeding it;
3. a 2-second deadline terminates a hanging worker and reports `ParserTimeout`;
4. closing either a worker child Job or the scan Job terminates the expected worker set;
5. a second pipe client is rejected;
6. wrong nonce/build, skipped or conflicting-duplicate sequence, and >1 MiB frame terminate the job/session while an exact retransmission is ignored idempotently;
7. duplicated handle is read-only; a write attempt returns access denied;
8. worker cannot use the handle after the parent disposes the job/process;
9. parent process remains alive after worker crash.

- [ ] **Step 7: Run the full Windows security lane and capture evidence**

```powershell
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber | ConvertTo-Json |
  Set-Content -Encoding utf8 artifacts/windows-security/os-build.json
$workerHash = Get-FileHash src/SecurityReview.Worker/bin/Release/net10.0-windows10.0.19041.0/win-x64/SecurityReview.Worker.exe -Algorithm SHA256
[pscustomobject]@{ Algorithm = $workerHash.Algorithm; Hash = $workerHash.Hash } |
  ConvertTo-Json | Set-Content -Encoding utf8 artifacts/windows-security/worker-hash.json
```

Expected: all nine invariants pass. Run this on at least one supported Windows 11 and each supported Windows 10 LTSC build before accepting the task.

- [ ] **Step 8: Commit the sandbox boundary separately**

```powershell
git add src/SecurityReview.Application/Abstractions/IWorkerLauncher.cs src/SecurityReview.Application/Abstractions/IFileHandleBroker.cs src/SecurityReview.Infrastructure/Windows/Native src/SecurityReview.Infrastructure/Windows/Sandbox src/SecurityReview.Worker tests/SecurityReview.WindowsSecurityTests/Sandbox
git commit -m "security: isolate parser workers with AppContainer and job limits"
```

## Task P0-T5: Add fail-closed sandbox preflight and M0 gate

**Files:**
- Create: `src/SecurityReview.Application/Scans/Preflight/SandboxSelfTestResult.cs`
- Create: `src/SecurityReview.Application/Scans/Preflight/ISandboxSelfTest.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Sandbox/WindowsSandboxSelfTest.cs`
- Create: `src/SecurityReview.Application/Scans/Preflight/ScanPreflightService.cs`
- Create: `src/SecurityReview.Desktop/Services/StartupHealthService.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/ScanPreflightServiceTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Sandbox/WindowsSandboxSelfTestTests.cs`
- Create: `docs/srs/evidence/m0-windows-sandbox.md`

**Interfaces:**
- Consumes: `IWorkerLauncher`, sandbox probe results, scan state.
- Produces: `SandboxSelfTestResult` and `ScanPreflightService.ValidateAsync`; later scan orchestration cannot schedule a parser without `Passed=true` for the current worker build/profile/policy fingerprint.

- [ ] **Step 1: Write fail-closed application tests**

```csharp
[Fact]
public async Task Preflight_fails_when_sandbox_self_test_fails()
{
    var selfTest = new StubSandboxSelfTest(SandboxSelfTestResult.Failed("network_denial_failed"));
    var service = new ScanPreflightService(selfTest);
    ScanPreflightResult result = await service.ValidateAsync(TestScan.Valid(), CancellationToken.None);
    Assert.False(result.CanStart);
    Assert.Contains(result.Errors, x => x.Code == "sandbox_unavailable");
}

[Fact]
public async Task Preflight_never_requests_unsandboxed_fallback()
{
    var launcher = new RecordingWorkerLauncher { Result = WorkerLaunchResult.Failed("appcontainer_create_failed") };
    var selfTest = new WindowsSandboxSelfTest(launcher);
    SandboxSelfTestResult result = await selfTest.RunAsync(CancellationToken.None);
    Assert.False(result.Passed);
    Assert.Single(launcher.Requests);
    Assert.All(launcher.Requests, request => Assert.True(request.RequireAppContainer));
}
```

- [ ] **Step 2: Run focused tests and observe failure**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~ScanPreflightServiceTests
```

Expected: FAIL because preflight types do not exist.

- [ ] **Step 3: Implement cached, fingerprint-bound self-test**

```csharp
public sealed record SandboxSelfTestResult(bool Passed, string Code, string WorkerSha256,
    string OsBuild, string ProfileSid, DateTimeOffset CheckedAtUtc)
{
    public static SandboxSelfTestResult Failed(string code) => new(false, code, "", "", "", DateTimeOffset.UtcNow);
}

public interface ISandboxSelfTest
{
    Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken);
}
```

`WindowsSandboxSelfTest` runs a bounded subset: AppContainer token, no loopback connection, duplicated read-only handle, wrong path denied, Job kill-on-close. Cache success for 24 hours only when worker SHA-256, OS build, AppContainer SID, executable manifest, and policy fingerprint all match. A failure is never cached as success and never activates a fallback launcher.

`ScanPreflightService.ValidateAsync` requires a valid root, active signed baseline, writable app-data/temp space, database health, and a passing sandbox result. It returns stable error codes; the UI may display help text but must not offer “continue anyway.”

- [ ] **Step 4: Add startup health display without parser bypass**

`StartupHealthService` exposes `Checking`, `Ready`, and `Blocked(code)` states. Desktop can open in blocked state so users can inspect diagnostics/history, but `Start scan` remains disabled. Display the OS build, worker hash prefix, and failure code without full local paths.

- [ ] **Step 5: Run M0 tests and write evidence**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Preflight
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity
```

Write `docs/srs/evidence/m0-windows-sandbox.md` with exact OS edition/build, SDK, worker SHA-256, test command, test count, exit code, AppContainer SID, Job limits, and each boundary assertion result. Do not include usernames, absolute paths, pipe names, file contents, or network addresses.

- [ ] **Step 6: Commit and hold the architecture gate**

```powershell
git add src/SecurityReview.Application/Scans/Preflight src/SecurityReview.Infrastructure/Windows/Sandbox src/SecurityReview.Desktop/Services/StartupHealthService.cs tests/SecurityReview.UnitTests/Scans/ScanPreflightServiceTests.cs tests/SecurityReview.WindowsSecurityTests/Sandbox/WindowsSandboxSelfTestTests.cs docs/srs/evidence/m0-windows-sandbox.md
git commit -m "security: fail closed when parser sandbox is unavailable"
```

P0 is complete only after the security owner reviews the evidence on all target Windows builds. If any invariant fails, stop before P1 and revise ADR-0001; do not weaken the tests.
