# Security Asset Content Review Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a portable Windows desktop client that statically scans release assets, locates sensitive information, records every coverage gap, optionally asks an intranet OpenAI-compatible LLM to review semantic candidates, and exports a fixed six-sheet XLSX report.

**Architecture:** A trusted WPF coordinator owns inventory, policy, detection, storage, LLM access, review, and reporting. Every untrusted parser runs in a no-network AppContainer worker constrained by a Windows Job Object and receives only duplicated read-only handles over a versioned named-pipe protocol. Sensitive local state uses AES-256-GCM envelope encryption with a DPAPI CurrentUser-protected key.

**Tech Stack:** C# 14, .NET 10.0.10 / SDK 10.0.302, WPF, Microsoft.Data.Sqlite, Open XML SDK, YamlDotNet event parser, PdfPig adapter, xUnit.net v3, PowerShell 7 build scripts.

## Global Constraints

- Target `win-x64`; V1 supports currently serviced Windows 11 x64 builds and Windows 10 Enterprise LTSC 2021 / IoT Enterprise LTSC 2021 x64 (build 19044+) only. Do not claim ordinary Windows 10 22H2 or LTSC 2019/2016 without a separate runtime/API compatibility decision and clean-VM evidence.
- Recheck the OS matrix at every release. Windows 10 Enterprise LTSC 2021 reaches its published support boundary on 2027-01-12, while the IoT edition has a different lifecycle; remove an edition from release notes as soon as either Microsoft or .NET no longer supports it.
- Deliver a self-contained portable directory ZIP; do not add an installer, Windows service, scheduled task, background updater, Docker/JRE/Python dependency, or system-wide configuration.
- Do not add login, RBAC, approval workflow, or a central server. Any internal user running the client can view complete values for scans in that Windows profile and can bulk-export them after the explicit XLSX warning. Windows identity is used only for local audit/DPAPI isolation, not for role-based masking; cross-profile history sharing is out of scope.
- Run one active scan at a time; target input is at most 10 GB and 100,000 files.
- Cold-start target is 5 seconds; idle working set target is 300 MB; aggregate scan working set target is 1.5 GB; local scan target is 30 minutes for the reference 10 GB/100,000-file corpus.
- Never execute assets, macros, scripts, JARs, installers, model objects, or container entrypoints. Never load Office/PDF external relationships.
- All untrusted parsing must run in an AppContainer worker with no network capability. Sandbox creation failure is fail-closed; there is no ordinary-process fallback in release builds.
- Worker input authority is a duplicated read-only file handle. A worker must not receive a user scan-root capability, LLM credential, rule signing key, database path, or unrestricted network capability.
- Archive defaults are depth 5, 100,000 entries per task, 50 GB or 100× input logical expansion (whichever is lower), 4 GB per entry, 1 MiB IPC/content frame, and 4 KiB content overlap.
- Every planned unit terminates as covered, partially covered, or not covered. Unsupported, failed, excluded, encrypted, unstable, over-limit, or unresolved semantic content must create a typed coverage gap.
- Eight `SENS-*` baseline categories always apply to every asset; asset-specific or local rules can add findings but cannot disable or weaken the signed baseline.
- Only one bounded semantic candidate (maximum 16 KiB UTF-8) may be sent per LLM request. Deterministic complete secrets are not sent. Release builds require HTTPS exact-origin, `AllowAutoRedirect=false`, `UseProxy=false`, and Windows certificate validation.
- Complete findings may appear only in encrypted local state, an explicitly opened details view, and a user-confirmed XLSX export. They must not appear in normal logs, diagnostics, HTTP logs, crash payloads, or test artifacts.
- Local sensitive payloads use AES-256-GCM with a fresh 12-byte nonce, 16-byte tag, and record-bound AAD. The 32-byte data key is protected with DPAPI CurrentUser. Fingerprints use an independently derived HMAC key.
- XLSX is the only V1 report format. The package must contain exactly six named sheets and no formulas, macros, hyperlinks, DDE, connections, or external relationships.
- Use TDD for domain, contracts, parsers, detectors, persistence, and report generation. A code task is complete only after its narrow test, the affected test project, formatting, and static build all pass.
- Use synthetic or irreversibly sanitized corpus data only. Never commit credentials, private endpoints, personal data, real customer/bank names, generated signing keys, `.env`, databases, logs, package output, or exported reports.
- Pin every NuGet/tool version centrally and commit `packages.lock.json`. Dependency changes occur in isolated commits with license, vulnerability, parser-corpus, and SBOM review.

---

## 1. Source of truth

Implementation decisions are governed in this order:

1. `docs/prd/prd-security-asset-content-review-tool.md` — approved product behavior and 60 acceptance criteria;
2. `docs/srs/srs-security-asset-content-review-tool.md` — technical contracts, limits, NFRs, and 35 verification lanes;
3. `docs/adr/0001-windows-native-modular-monolith-and-sandboxed-parser-workers.md` — architecture and fail-closed sandbox decision;
4. this master plan — task sequence, repository shape, dependency versions, and release gates;
5. the seven executable phase plans below — file-level TDD steps.

When a lower item conflicts with a higher item, stop the affected task, record the conflict in a new ADR or requirements change, and do not silently change behavior.

## 2. Plan set and execution order

| Phase | Detailed plan | Deliverable | Entry dependency | Exit gate |
| --- | --- | --- | --- | --- |
| P0 | [Foundation and Windows sandbox](2026-07-20-security-review-00-foundation-sandbox.md) | Reproducible solution, scan/coverage domain, IPC contract, proven AppContainer boundary | Supported Windows development VM | Worker has no network/root browse, can read one duplicated handle, crash/OOM is isolated |
| P1 | [Inventory and parser core](2026-07-20-security-review-01-inventory-parser-core.md) | Stable inventory, Manifest, ADS/reparse protection, streaming text/archive parsing, orchestration | P0 | File/directory scan produces deterministic chunks and complete coverage ledger |
| P2 | [Format parser adapters](2026-07-20-security-review-02-format-parsers.md) | Structured, Office, PDF, Python, JAR, binary, OCI/Docker, model metadata coverage | P1 | Golden corpus resolves every expected location or typed gap |
| P3 | [Rule packs and detection](2026-07-20-security-review-03-rules-detection.md) | Signed offline rules, effective policy, deterministic detectors, grouped findings | P1; P2 adapters can land incrementally | Eight-category baseline cannot be weakened; deterministic release corpus is 100% detected |
| P4 | [Encrypted persistence, review, diff, cache](2026-07-20-security-review-04-persistence-review-cache.md) | SQLite migrations, crypto, history, review/exception, retention, strict cache and diff | P0 domain; P1 inventory IDs; P3 finding contracts | Canary plaintext absent; tamper fails; cache invalidation matrix and exception expiry pass |
| P5 | [LLM adapter and WPF desktop](2026-07-20-security-review-05-llm-desktop.md) | Exact-origin intranet LLM, orchestration, scan/progress/results/preview/settings UI | P1, P3, P4 | Prompt-injection corpus falls back safely; end-to-end desktop scan remains responsive |
| P6 | [XLSX, diagnostics, performance, release](2026-07-20-security-review-06-reporting-release.md) | Six-sheet report, diagnostic bundle, full corpus gates, SBOM, portable ZIP and pilot package | P0–P5 | 35 VT lanes pass on target Windows; clean-VM package and support material approved |

P2 and P3 may run in parallel after P1 freezes `ContentChunk`, `SourceLocator`, `CoverageGap`, and `DetectionCandidate`. P4 may begin after P0/P1 domain IDs stabilize. P5 integration begins only after P3 and P4 expose real ports; it must not build throwaway duplicate repositories or rule engines.

## 3. Suggested staffing and calendar

The estimates assume two experienced C# engineers, one security engineer at 50%, one rules/data engineer at 50%, and one QA engineer from P1 onward. They are planning ranges, not release promises.

| Calendar window | Primary work | People | Expected checkpoint |
| --- | --- | --- | --- |
| Weeks 1–2 | P0 solution/domain/IPC and sandbox spike | C# A, security | Architecture go/no-go on target Windows |
| Weeks 3–5 | P1 inventory, file broker, text/archive core | C# A, C# B, QA | Local scan CLI/harness with coverage ledger |
| Weeks 5–9 | P2 format adapters; P3 rules/detectors in parallel | C# A, C# B, rules, QA | Cross-format deterministic scanner |
| Weeks 8–11 | P4 encrypted history, review, exception, diff/cache | C# B, security, QA | Durable local scan and rescan comparison |
| Weeks 10–13 | P5 LLM adapter and WPF workflow | C# A, C# B, security, QA | Feature-complete internal alpha |
| Weeks 13–16 | P6 reporting, performance, hardening, clean VM | whole team | Pilot candidate |
| Weeks 17–18 | Pilot feedback, corpus corrections, release review | whole team + pilot users | Internal V1 |

With one developer, preserve the phase order and plan for roughly 26–34 engineering weeks. Do not shorten the schedule by moving untrusted parsers into the WPF process or by removing coverage-gap accounting.

## 4. Toolchain and pinned dependencies

As of 2026-07-20, use these stable versions. The first bootstrap commit records them in `global.json`, `Directory.Packages.props`, and `.config/dotnet-tools.json`:

| Dependency | Version | Purpose | Approval note |
| --- | --- | --- | --- |
| .NET SDK | 10.0.302 | Build C# 14/.NET 10 and WPF | Exact SDK; update via dedicated servicing commit |
| Microsoft.Data.Sqlite | 10.0.10 | Lightweight ADO.NET SQLite access | No EF Core; explicit SQL/migrations |
| System.Security.Cryptography.ProtectedData | 10.0.10 | DPAPI CurrentUser | Windows-only infrastructure adapter |
| System.Text.Encoding.CodePages | 10.0.10 | GB18030 and legacy code pages | Register once in worker startup |
| DocumentFormat.OpenXml | 3.5.1 | Open XML parse/report | Only worker parses input Office; trusted reporter writes output |
| YamlDotNet | 18.1.0 | Low-level YAML event parsing | Do not use object deserialization; enforce alias/depth/event limits |
| PdfPig | 0.1.14 | PDF text/metadata/embedded-file adapter | API is pre-1.0; isolated adapter and full corpus required for upgrades |
| xunit.v3 | 3.2.2 | Unit/contract/integration tests | Stable v3 package |
| xunit.runner.visualstudio | 3.1.5 | `dotnet test`/IDE adapter | `PrivateAssets=all` |
| Microsoft.NET.Test.Sdk | 18.8.1 | VSTest host | `PrivateAssets=all` |
| coverlet.collector | 10.0.1 | Coverage collection | `PrivateAssets=all`; coverage is signal, not sole quality gate |
| Microsoft.Sbom.DotNetTool | 4.1.5 | SPDX SBOM for published directory | Repo-local tool manifest |

Official version references: [.NET 10.0 download](https://dotnet.microsoft.com/en-us/download/dotnet/10.0), [.NET 10 supported OS matrix](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md), [Windows 10 Enterprise LTSC 2021 release health](https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-21h2), [Windows 10 IoT Enterprise LTSC 2021 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-iot-enterprise-ltsc-2021), [Microsoft.Data.Sqlite](https://www.nuget.org/packages/Microsoft.Data.Sqlite/), [Open XML SDK](https://www.nuget.org/packages/DocumentFormat.OpenXml/), [YamlDotNet](https://www.nuget.org/packages/YamlDotNet/), [PdfPig](https://www.nuget.org/packages/PdfPig/0.1.14), [xUnit.net v3](https://www.nuget.org/packages/xunit.v3/3.2.2), [SBOM tool](https://www.nuget.org/packages/Microsoft.Sbom.DotNetTool/).

Do not add Polly, an OpenAI SDK, an ORM, a DI container, a logging framework, a browser control, Office COM, Docker SDK, Java parser/runtime, Python runtime, or native decompression package in V1. The required retry, circuit breaker, HTTP contract, SQL access, composition root, JSONL diagnostics, and bounded parsers are small and security-sensitive enough to keep explicit.

## 5. Repository layout

The P0 plan creates this structure. Each file has one responsibility; do not combine parser adapters, repositories, or view models into large catch-all files.

```text
SecurityReviewTool.sln
global.json
Directory.Build.props
Directory.Packages.props
NuGet.config
.editorconfig
.gitignore
.config/dotnet-tools.json
build/
  build.ps1
  test.ps1
  package.ps1
  verify-package.ps1
  generate-sbom.ps1
src/
  SecurityReview.Domain/
    Assets/             # asset/category identifiers and manifest domain values
    Scans/              # scan state, coverage, progress, inventory identities
    Findings/           # candidates, groups, occurrences, source locators, severity/confidence
    Reviews/            # decisions, exceptions, diff state
    Rules/              # rule identifiers and effective-policy values
  SecurityReview.Application/
    Abstractions/       # ports consumed by use cases
    Scans/              # create/start/cancel/finalize orchestration
    Reviews/            # review/exception/rescan use cases
    Rules/              # import/activate use cases
    Reporting/          # export use case
  SecurityReview.ParserContracts/
    Protocol/           # frame header, message types, codec and validation
    Parsing/            # ParseJob, chunks, location maps, parser result/gap DTOs
  SecurityReview.Parsers/
    Core/               # sniffer, limits, parser registry, virtual paths
    Text/ Structured/ Archives/ OpenXml/ Pdf/ Jvm/ Binary/ Oci/ Models/
  SecurityReview.RulePack/
    Schema/ Validation/ Signing/ Policy/ Detection/
  SecurityReview.Infrastructure/
    Windows/            # AppContainer, Job, handles, ADS/reparse APIs
    Persistence/        # SQLite, migrations, crypto, repositories
    Llm/                # exact-origin HTTP adapter and credential store
    Reporting/          # Open XML XLSX writer/validator
    Diagnostics/        # redacted JSONL and bundle exporter
  SecurityReview.Worker/
    Program.cs
    WorkerHost.cs
  SecurityReview.Desktop/
    App.xaml
    CompositionRoot.cs
    Views/
    ViewModels/
    Services/
tools/
  SecurityReview.RulePackBuilder/
  SecurityReview.CorpusTool/
tests/
  SecurityReview.UnitTests/
  SecurityReview.ContractTests/
  SecurityReview.ParserCorpusTests/
  SecurityReview.IntegrationTests/
  SecurityReview.WindowsSecurityTests/
  SecurityReview.PerformanceTests/
  Corpus/
    corpus-manifest.json
    Text/ Structured/ Archives/ Office/ Pdf/ Jvm/ Binary/ Oci/ Models/ Adversarial/
rules/
  schemas/
  baseline/             # normalized built-in public rule data, never private entities
  templates/
docs/
  adr/
  prd/
  srs/
  operations/
```

## 6. Cross-plan interface registry

These names are fixed before parallel implementation. A type change requires updating every consuming phase plan and a contract test in the same commit.

### 6.1 Domain identifiers and enums

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
public readonly record struct CategoryId(string Value);
public readonly record struct AssetTypeId(string Value);

public enum ScanStatus { Draft, Preflight, Running, Cancelling, Completed, Partial, Cancelled, Failed, Interrupted }
public enum CoverageStatus { Covered, PartiallyCovered, NotCovered }
public enum FindingKind { SensitiveContent, AssetCompliance }
public enum Severity { Critical, High, Medium, Low, Info }
public enum DetectionConfidence { High, Medium, Low }
public enum ReviewStatus { Pending, ConfirmedRisk, FalsePositive, ApprovedException, RemediatedAwaitingRescan }
public enum DifferenceStatus { New, Persistent, Resolved, ReappearedAfterRuleChange, UnreviewableThisRun }
```

### 6.2 Scan and coverage contracts

```csharp
public sealed record CoverageGap(
    Guid GapId,
    ScanId ScanId,
    FileId? FileId,
    string VirtualPath,
    string FormatId,
    string Stage,
    GapReason Reason,
    string DetailCode,
    long? PlannedBytes,
    long? ProcessedBytes,
    DateTimeOffset CreatedAtUtc);

public interface ICoverageLedger
{
    ValueTask RecordCoveredAsync(ScanId scanId, FileId fileId, string unitId, CancellationToken cancellationToken);
    ValueTask RecordGapAsync(CoverageGap gap, CancellationToken cancellationToken);
    ValueTask<CoverageSummary> SummarizeAsync(ScanId scanId, CancellationToken cancellationToken);
}

public interface IScanOrchestrator
{
    Task<ScanId> CreateAsync(CreateScanCommand command, CancellationToken cancellationToken);
    Task RunAsync(ScanId scanId, IProgress<ScanProgress> progress, CancellationToken cancellationToken);
    Task CancelAsync(ScanId scanId, CancellationToken cancellationToken);
}
```

### 6.3 Parser contracts

```csharp
public sealed record ParseJob(
    int ProtocolVersion,
    ScanId ScanId,
    JobId JobId,
    long InputHandle,
    long DeclaredLength,
    string FormatHint,
    string DisplayVirtualPath,
    ParseLimits Limits,
    IReadOnlyList<string> RequestedExtractors);

public sealed record ContentChunk(
    int ProtocolVersion,
    JobId JobId,
    long Sequence,
    string VirtualPath,
    string FormatId,
    ContentKind ContentKind,
    string? Encoding,
    string Text,
    long SourceStart,
    long SourceLength,
    IReadOnlyList<LocationMapEntry> LocationMap,
    bool IsFinal);

public interface IFormatParser
{
    string ParserId { get; }
    Version ParserVersion { get; }
    bool CanParse(FormatProbe probe);
    IAsyncEnumerable<ParserEvent> ParseAsync(ParserInput input, ParseContext context, CancellationToken cancellationToken);
}
```

`ParserEvent` is a closed hierarchy of `ChunkProduced`, `ChildDiscovered`, `GapProduced`, and `ParseCompleted`. Workers emit it; only the trusted coordinator converts validated events into domain records.

### 6.4 Rule and detection contracts

```csharp
public interface IRulePackValidator
{
    Task<RulePackValidationResult> ValidateAsync(Stream package, RulePackValidationContext context, CancellationToken cancellationToken);
}

public interface IEffectivePolicyProvider
{
    Task<EffectivePolicy> BuildAsync(RulePackId rulePackId, IReadOnlySet<AssetTypeId> assetTypes,
        LocalAdditivePolicy? localPolicy, CancellationToken cancellationToken);
}

public interface IDetector
{
    DetectorId Id { get; }
    IAsyncEnumerable<DetectionCandidate> DetectAsync(ContentChunk chunk, EffectivePolicy policy,
        CancellationToken cancellationToken);
}

public sealed record DetectionCandidate(
    CandidateId CandidateId,
    ScanId ScanId,
    FileId FileId,
    FindingKind Kind,
    CategoryId CategoryId,
    RuleId RuleId,
    DetectorId DetectorId,
    Severity Severity,
    DetectionConfidence Confidence,
    string Value,
    string Context,
    SourceLocator Locator,
    bool RequiresSemanticReview);
```

### 6.5 Persistence, LLM, review, and report ports

```csharp
public interface IScanRepository
{
    Task InsertAsync(ScanRun scan, CancellationToken cancellationToken);
    Task<ScanRun?> GetAsync(ScanId scanId, CancellationToken cancellationToken);
    Task<bool> TryTransitionAsync(ScanId scanId, ScanStatus expected, ScanStatus next,
        DateTimeOffset occurredAtUtc, CancellationToken cancellationToken);
}

public interface ISemanticReviewer
{
    Task<LlmReviewResult> ReviewAsync(SemanticReviewRequest request, CancellationToken cancellationToken);
}

public interface IReviewService
{
    Task<ReviewDecision> RecordAsync(RecordReviewCommand command, CancellationToken cancellationToken);
    Task<ExceptionGrant> GrantExceptionAsync(GrantExceptionCommand command, CancellationToken cancellationToken);
}

public interface IXlsxReportExporter
{
    Task<ReportExportResult> ExportAsync(ExportXlsxCommand command, CancellationToken cancellationToken);
}
```

## 7. Build and test command contract

All commands run from the repository root in PowerShell 7 on Windows. Phase plans may run narrower project filters first.

```powershell
dotnet --version
dotnet restore SecurityReviewTool.sln --locked-mode
dotnet build SecurityReviewTool.sln -c Release --no-restore
dotnet test SecurityReviewTool.sln -c Release --no-build --logger "trx;LogFileName=tests.trx"
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
dotnet list SecurityReviewTool.sln package --vulnerable --include-transitive
dotnet list SecurityReviewTool.sln package --deprecated
pwsh ./build/build.ps1 -Configuration Release
pwsh ./build/test.ps1 -Lane Unit,Contract,Integration
```

Expected result for a completed task: every command exits 0; the targeted failing test was observed before implementation; no unexpected skipped tests; test output contains no corpus content or complete finding value.

Windows-only lanes run explicitly and never appear as a silent skip in release validation:

```powershell
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity
pwsh ./build/test.ps1 -Lane ParserCorpus -RequireCorpus
pwsh ./build/test.ps1 -Lane Performance -RequirePerformanceHost
```

## 8. Task inventory and dependencies

| Task | Name | Depends on | Primary SRS |
| --- | --- | --- | --- |
| P0-T1 | Reproducible solution and quality baseline | none | SRS-F-001, SRS-NFR-016 |
| P0-T2 | Scan state and coverage domain | P0-T1 | SRS-F-002, SRS-F-013, SRS-F-017 |
| P0-T3 | Versioned parser IPC | P0-T1 | SRS-F-008 |
| P0-T4 | AppContainer/Job/handle/pipe spike | P0-T3 | SRS-F-008, SRS-F-019 |
| P0-T5 | Fail-closed sandbox preflight | P0-T2, P0-T4 | SRS-F-001, SRS-F-008 |
| P1-T1 | Manifest and scan-root model | P0-T2 | SRS-F-003 |
| P1-T2 | Windows inventory, ADS, reparse and identity | P0-T4, P1-T1 | SRS-F-002, SRS-F-004 |
| P1-T3 | Stable hashing and read-only file broker | P1-T2 | SRS-F-002, SRS-F-008 |
| P1-T4 | Format sniffing, encoding and text chunks | P0-T3, P1-T3 | SRS-F-004, SRS-F-005 |
| P1-T5 | Bounded ZIP/TAR/GZip recursion | P1-T4 | SRS-F-005, SRS-F-008 |
| P1-T6 | Worker pool, orchestration, progress and cancel | P0-T5, P1-T3..T5 | SRS-F-002, SRS-F-017 |
| P2-T1 | JSON/XML/CSV/YAML parsers | P1-T4 | SRS-F-005 |
| P2-T2 | Open XML and macro-visible strings | P1-T5 | SRS-F-005 |
| P2-T3 | PDF text/metadata/attachments | P1-T5 | SRS-F-005 |
| P2-T4 | Python/JVM/JAR/PE/ELF | P1-T4, P1-T5 | SRS-F-006 |
| P2-T5 | Docker archive and OCI layouts | P1-T5 | SRS-F-007 |
| P2-T6 | Safe model metadata | P1-T4, P1-T5 | SRS-F-005, SRS-F-006 |
| P2-T7 | Cross-format location/coverage corpus gate | P2-T1..T6 | SRS-F-018 |
| P3-T1 | Rule schema and built-in eight-category baseline | P0-T1 | SRS-F-009, SRS-F-010 |
| P3-T2 | Excel RulePackBuilder and ECDSA signing | P3-T1 | SRS-F-010 |
| P3-T3 | Rule import and effective-policy merge | P3-T1, P3-T2 | SRS-F-009, SRS-F-010 |
| P3-T4 | Detector pipeline, regex and validators | P1-T4, P3-T3 | SRS-F-011 |
| P3-T5 | Network/entity/dictionary/placeholder/license detectors | P3-T4 | SRS-F-011 |
| P3-T6 | Candidate merge, provenance and conclusion | P3-T4, P3-T5 | SRS-F-013 |
| P3-T7 | Deterministic rule release corpus | P3-T2..T6 | SRS-F-018 |
| P4-T1 | SQLite connection and forward-only migrations | P0-T2 | SRS-F-015 |
| P4-T2 | DPAPI keyring, AES-GCM payloads and HMAC | P4-T1 | SRS-F-015 |
| P4-T3 | Scan/file/finding/coverage repositories | P4-T2, P3-T6 | SRS-F-013, SRS-F-015 |
| P4-T4 | Recovery, retention and clear-local-data | P4-T3 | SRS-F-015 |
| P4-T5 | Review decisions and exact exceptions | P4-T3 | SRS-F-014 |
| P4-T6 | Strict stage cache and rescan diff | P4-T3, P4-T5 | SRS-F-014 |
| P5-T1 | LLM configuration, credential and exact-origin HTTP | P4-T2 | SRS-F-012, SRS-F-019 |
| P5-T2 | Semantic minimization, schema and injection fallback | P3-T6, P5-T1 | SRS-F-012 |
| P5-T3 | Retry, circuit, queue and semantic cache | P4-T6, P5-T2 | SRS-F-012 |
| P5-T4 | End-to-end application orchestrator | P1-T6, P3-T6, P4-T3, P5-T3 | SRS-F-002, SRS-F-013, SRS-F-017 |
| P5-T5 | WPF shell, composition and navigation | P5-T4 ports | SRS-F-001, SRS-F-017 |
| P5-T6 | Scan setup/progress/findings/coverage views | P5-T5 | SRS-F-003, SRS-F-013, SRS-F-017 |
| P5-T7 | Safe preview/review/rules/LLM/history views | P4-T5, P5-T3, P5-T6 | SRS-F-010, SRS-F-012, SRS-F-014, SRS-F-017 |
| P6-T1 | Six-sheet XLSX writer and security validator | P4-T3, P4-T5 | SRS-F-016 |
| P6-T2 | Redacted diagnostics bundle | P0-T5, P4-T3, P5-T3 | SRS-F-019 |
| P6-T3 | Full end-to-end corpus and conclusion checks | P2-T7, P3-T7, P5-T7, P6-T1 | SRS-F-018 |
| P6-T4 | Performance, cancellation and reliability harness | P6-T3 | SRS-NFR-001..015 |
| P6-T5 | Portable publish, manifest, SBOM and package verify | P6-T1..T4 | SRS-F-001, SRS-NFR-016 |
| P6-T6 | Clean-VM matrix, pilot runbook and release evidence | P6-T5 | all 35 VT lanes |

## 9. Requirement coverage

| Business objective | PRD requirement | Acceptance criteria | SRS requirement | Implementing tasks | Verification anchor |
| --- | --- | --- | --- | --- | --- |
| BRD-OBJ-002 | REQ-001 | AC-001 | SRS-F-001 | P0-T1, P0-T5, P5-T5, P6-T5/6 | VT-001, VT-002 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-002 | AC-002, AC-003, AC-004 | SRS-F-002 | P0-T2, P1-T2/3/6, P5-T4 | VT-003 |
| BRD-OBJ-001 | REQ-003 | AC-005, AC-006 | SRS-F-003 | P1-T1, P5-T6 | VT-004 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-004 | AC-007, AC-008, AC-009 | SRS-F-004 | P1-T2/4 | VT-005, VT-006 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-005 | AC-010, AC-011, AC-012 | SRS-F-005 | P1-T4/5, P2-T1/2/3 | VT-007, VT-008 |
| BRD-OBJ-001 | REQ-006 | AC-013, AC-014, AC-015 | SRS-F-006 | P2-T4, P2-T6 | VT-009 |
| BRD-OBJ-001 | REQ-007 | AC-016, AC-017 | SRS-F-007 | P2-T5 | VT-010 |
| BRD-OBJ-003 | REQ-008 | AC-018, AC-019, AC-020, AC-021 | SRS-F-008 | P0-T3/4/5, P1-T3/5/6 | VT-011, VT-012, VT-013, VT-014 |
| BRD-OBJ-001 | REQ-009 | AC-022, AC-023, AC-024 | SRS-F-009 | P3-T1/3 | VT-015 |
| BRD-OBJ-003 | REQ-010 | AC-025, AC-026, AC-027 | SRS-F-010 | P3-T1/2/3, P5-T7 | VT-016 |
| BRD-OBJ-001 | REQ-011 | AC-028, AC-029, AC-030, AC-031 | SRS-F-011 | P3-T4/5 | VT-017 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-012 | AC-032, AC-033, AC-034, AC-035 | SRS-F-012 | P5-T1/2/3 | VT-018, VT-019, VT-020 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-013 | AC-036, AC-037, AC-038, AC-039, AC-040 | SRS-F-013 | P3-T6, P4-T3, P5-T6 | VT-021 |
| BRD-OBJ-003 | REQ-014 | AC-041, AC-042, AC-043, AC-044 | SRS-F-014 | P4-T5/6, P5-T7 | VT-022, VT-023 |
| BRD-OBJ-002, BRD-OBJ-003 | REQ-015 | AC-045, AC-046, AC-047 | SRS-F-015 | P4-T1/2/3/4 | VT-024, VT-025 |
| BRD-OBJ-003 | REQ-016 | AC-048, AC-049, AC-050 | SRS-F-016 | P6-T1 | VT-026, VT-027 |
| BRD-OBJ-002 | REQ-017 | AC-051, AC-052, AC-053, AC-054 | SRS-F-017 | P1-T6, P5-T4/5/6/7 | VT-028, VT-029 |
| BRD-OBJ-001, BRD-OBJ-003 | REQ-018 | AC-055, AC-056, AC-057 | SRS-F-018 | P2-T7, P3-T7, P6-T3/4 | VT-030, VT-031, VT-032 |
| BRD-OBJ-002, BRD-OBJ-003 | REQ-019 | AC-058, AC-059, AC-060 | SRS-F-019 | P0-T4, P5-T1/3, P6-T2/5/6 | VT-033, VT-034, VT-035 |

No product requirement is deferred beyond V1 by this plan. Unsupported formats described by the SRS remain explicit coverage gaps; they are not omitted work.

### 9.1 Non-functional requirement coverage

| NFR | Implementing tasks | Measured gate |
| --- | --- | --- |
| SRS-NFR-001 | P5-T5, P6-T4, P6-T6 | 30 cold launches; interactive-window P95 ≤5 s |
| SRS-NFR-002 | P5-T5, P6-T4 | idle 60 s working-set P95 ≤300 MiB |
| SRS-NFR-003 | P0-T4, P1-T6, P6-T4 | main+workers peak ≤1.5 GiB |
| SRS-NFR-004 | P1-T6, P2-T7, P3-T7, P6-T4 | 10 GB/100k local stage P95 ≤30 min |
| SRS-NFR-005 | P1-T4/5, P2 adapters, P6-T4 | 1/5/20 GB memory-growth test |
| SRS-NFR-006 | P1-T6, P5-T4/6, P6-T4 | no new scheduling after 2 s |
| SRS-NFR-007 | P5-T5/6/7, P6-T4 | input dispatch P95 ≤100 ms; progress ≤500 ms |
| SRS-NFR-008 | P0-T4/5, P1-T6, P6-T4 | crash/hang/OOM affects current job only |
| SRS-NFR-009 | P1-T6, P2-T7, P6-T3 | expected coverage-gap reconciliation 100% |
| SRS-NFR-010 | P3-T7, P6-T3 | deterministic Critical/High expected detection 100% |
| SRS-NFR-011 | P5-T2/3, P6-T3/6 | fixed model/prompt semantic recall ≥95%, false-positive rate reported |
| SRS-NFR-012 | P0-T4/5, P6-T3/6 | worker loopback/DNS/LAN/Internet denial |
| SRS-NFR-013 | P4-T2/3, P5-T3, P6-T2/3 | recursive canary scan finds zero plaintext leakage |
| SRS-NFR-014 | P4-T2/3, P6-T3 | offline encrypted-field and tamper tests |
| SRS-NFR-015 | P1-T6, P3-T7, P6-T3/4 | normalized duplicate-run result set identical |
| SRS-NFR-016 | P0-T1, P6-T5/6 | locked restore, SBOM, vulnerability and package-manifest gate |

### 9.2 Verification-lane ownership

Every SRS verification lane has one or more implementation owners and a final evidence owner. P6-T3 maintains `tests/Acceptance/acceptance-manifest.json`; P6-T6 runs the exact packaged binaries on the clean-VM matrix and archives the signed result index.

| Verification lane | Primary implementation tasks | Final evidence task |
| --- | --- | --- |
| VT-001 | P5-T5, P6-T5 | P6-T6 |
| VT-002 | P5-T5, P6-T4, P6-T5 | P6-T6 |
| VT-003 | P0-T2, P1-T3, P5-T4 | P6-T3 |
| VT-004 | P1-T1, P3-T3, P5-T6 | P6-T3 |
| VT-005 | P1-T4, P2-T1, P2-T2, P2-T3 | P6-T3 |
| VT-006 | P1-T2, P1-T3 | P6-T3 |
| VT-007 | P1-T4, P2-T1 | P6-T3 |
| VT-008 | P2-T2, P2-T3 | P6-T3 |
| VT-009 | P2-T4, P2-T6 | P6-T3 |
| VT-010 | P2-T5 | P6-T3 |
| VT-011 | P0-T5, P2-T2, P2-T4, P2-T5, P2-T6 | P6-T3 |
| VT-012 | P0-T4, P0-T5 | P6-T3, P6-T6 |
| VT-013 | P1-T5, P2-T4, P2-T5 | P6-T3 |
| VT-014 | P0-T5, P1-T5, P1-T6, P2-T7 | P6-T3 |
| VT-015 | P3-T1, P3-T3, P3-T7 | P6-T3 |
| VT-016 | P3-T1, P3-T2, P3-T3, P3-T7 | P6-T3 |
| VT-017 | P3-T4, P3-T5, P3-T7 | P6-T3 |
| VT-018 | P5-T2 | P6-T3 |
| VT-019 | P5-T2 | P6-T3 |
| VT-020 | P5-T3 | P6-T3 |
| VT-021 | P3-T6, P4-T3, P5-T6 | P6-T3 |
| VT-022 | P4-T5, P5-T7 | P6-T3 |
| VT-023 | P4-T6 | P6-T3 |
| VT-024 | P4-T2, P4-T3 | P6-T3 |
| VT-025 | P4-T4 | P6-T3 |
| VT-026 | P6-T1 | P6-T3 |
| VT-027 | P6-T1 | P6-T3 |
| VT-028 | P1-T6, P5-T4, P5-T6, P6-T4 | P6-T6 |
| VT-029 | P5-T7 | P6-T3 |
| VT-030 | P3-T7 | P6-T3 |
| VT-031 | P5-T2, P5-T3 | P6-T3, P6-T6 |
| VT-032 | P2-T7 | P6-T3 |
| VT-033 | P0-T4, P0-T5, P5-T1 | P6-T3, P6-T6 |
| VT-034 | P5-T1, P5-T2, P5-T3 | P6-T3, P6-T6 |
| VT-035 | P4-T2, P4-T3, P5-T3, P6-T2 | P6-T3, P6-T6 |

## 10. Milestone definitions of done

### M0 — Architecture proven

- P0 tests pass on every target Windows build;
- process-token inspection proves AppContainer SID and absence of network capability;
- canary listeners prove loopback, DNS, LAN, and Internet denial;
- worker reads only the duplicated handle and cannot enumerate a sibling user file;
- crash, hang, memory, child-process, pipe spoof, oversize frame, and parent-exit tests pass;
- security owner signs the spike evidence before P1 treats the boundary as real.

### M1 — Local deterministic scanner

- P1–P3 are complete;
- file/directory/Docker inputs produce stable inventory, chunks, findings, exact locators, and coverage gaps;
- all eight baseline categories are active for unknown assets;
- parser failures continue other files and cannot produce `Completed`;
- deterministic high-risk release corpus has 100% expected detection.

### M2 — Feature-complete desktop alpha

- P4–P5 are complete;
- encrypted history, review, exception, diff/cache, LLM and WPF flows work end to end;
- database/keyring/log/temp/capture canary scan finds no plaintext leakage;
- prompt-injection/invalid-response/unavailable LLM cases remain reviewable and make the task Partial only when applicable;
- UI remains responsive during the reference scan and cancel stops new work within 2 seconds.

### M3 — Pilot candidate

- P6 is complete and all 35 VT lanes have machine-readable evidence;
- six-sheet XLSX validator rejects formulas, external relationships, macros, DDE and wrong sheet/row counts;
- 10 GB/100k performance and 1.5 GB aggregate memory goals pass on the fixed reference host;
- portable ZIP is self-contained, manifest-hashed, SBOM-generated, vulnerability-reviewed and clean-VM tested;
- support documentation explains coverage gaps, bounded conclusions, LLM configuration, rule import, diagnostics and uninstall/clear-data behavior.

## 11. Review and commit discipline

Each task follows red/green/refactor and ends with a local commit. Use these prefixes:

```text
build: repository/toolchain/package changes
feat: user-visible or domain capability
fix: verified defect correction
test: corpus or test-only changes
docs: contracts, operations, ADR or evidence
security: hardening or security-boundary changes
```

Before each commit:

```powershell
dotnet test <narrow-test-project> -c Release
dotnet build SecurityReviewTool.sln -c Release --no-restore
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
git diff --check
git status --short
```

Do not combine dependency upgrades with parser or detector behavior. Do not approve a parser change from code inspection alone; attach its focused corpus result. Do not approve a security-boundary change without WindowsSecurity evidence.

## 12. Risk-driven checkpoints

| Risk | Earliest proof | Stop condition | Resolution path |
| --- | --- | --- | --- |
| Enterprise policy blocks AppContainer/profile/ACL creation | P0-T4 | No-admin target machine cannot satisfy all sandbox invariants | Revisit ADR before parser work; no unsandboxed fallback |
| Actual estate contains unsupported Windows 10 | Before P0 | A required build is outside .NET 10 support | Upgrade estate or approve a new runtime ADR with servicing plan |
| PdfPig/YamlDotNet crashes on malicious corpus | P2-T1/T3 | Reproducible escape/OOM beyond worker limits or unacceptable gaps | Replace adapter/library or narrow documented coverage; keep gap explicit |
| 30-minute target conflicts with 100% archive expansion | P1-T5 and P6-T4 | Reference corpus exceeds target within safe limits | Profile and optimize streaming/concurrency; do not raise safety caps silently |
| LLM endpoint lacks HTTPS/compatible request mode/limits | Before P5 | Production endpoint cannot meet exact-origin TLS and the strict parsed response contract in any supported mode | Keep semantic review disabled/Partial and resolve with LLM owner |
| Rule corpus cannot reach deterministic 100% high-risk detection | P3-T7 | Any expected high-risk sample is missed | Block rule pack/client release; fix detector/rule/locator |
| Full-value XLSX creates operational leakage | P6-T1/6 | Distribution workflow cannot protect reports | Keep explicit warning; product owner must change requirement or distribution control |

## 13. Implementation start checklist

- [ ] Name the client engineering, security engineering, rules, QA, and release owners in the internal project tracker.
- [ ] Record exact Windows editions/builds used by developers, CI, performance, and pilot users.
- [ ] Provision a non-production intranet LLM endpoint with HTTPS, a synthetic test model/config, rate limits, and a credential that contains no production authority.
- [ ] Create the rule-signing procedure: offline ECDSA P-256 key custody, two-person package approval, signer ID, and public-key rotation.
- [ ] Approve the pinned package licenses and internal NuGet source policy; mirror packages if development machines cannot access nuget.org.
- [ ] Create a secure, non-repository location for adversarial corpora that cannot be committed, and a sanitized corpus subset that can be committed.
- [ ] Fix the reference performance host specification and preserve its Defender/power settings in test evidence.
- [ ] Execute P0 in order; do not begin broad parser implementation before M0 passes.

## 14. Execution handoff

Implement one detailed phase plan at a time. Within a phase, execute tasks in listed order unless the dependency table explicitly allows parallel work. At the end of every phase, run its full exit gate and update the SRS walkthrough with commands, OS build, package/rule/parser versions, exit codes, and artifact hashes.

Recommended first implementation command after creating a Git worktree and installing .NET SDK 10.0.302:

```powershell
pwsh -NoProfile -File ./build/build.ps1 -Configuration Release
```

That script is created in P0-T1; before it exists, execute the exact bootstrap commands in the P0 plan.
