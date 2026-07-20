# Security Review P6 Reporting Quality and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a safe fixed six-sheet XLSX report, export redacted diagnostics, prove all functional/security/performance lanes, and package a repeatable, verifiable self-contained Windows ZIP with manifest, SBOM, verification evidence, and pilot runbooks.

**Architecture:** Reporting reads immutable encrypted scan projections, writes all source data as Open XML text cells to a temporary package, validates the package allowlist, then atomically renames it. Diagnostics use an event/field allowlist rather than post-hoc masking. Release scripts publish Desktop and Worker separately into one verified directory, generate hashes/SBOM, optionally Authenticode-sign, and test the exact ZIP on clean non-admin VMs.

**Tech Stack:** Open XML SDK 3.5.1, Microsoft SBOM Tool 4.1.5, PowerShell 7, .NET 10 self-contained publish, Windows performance counters/ETW/pktmon, xUnit.net v3.

## Global Constraints

- XLSX is the only report format and contains exactly: 扫描摘要, 敏感内容发现, 资产合规发现, 未覆盖内容, 文件清单, 复核记录.
- Complete finding values and every occurrence are exported after an explicit warning; all source strings remain text and no formula/macro/link/DDE/connection/external relation is allowed.
- Export is temp-write → close → reopen/validate → hash → atomic rename; failure leaves no partial target.
- Diagnostics contain no asset body, complete finding, LLM body/header, credential, sensitive path, database, keyring, rule private data, or report.
- Release validation covers all 19 SRS-F, 16 NFR, and 35 VT identifiers with machine-readable evidence.
- Package is `win-x64`, self-contained, folder-based, untrimmed, without PDB/test/corpus/local data.
- Broad internal release requires Authenticode when an enterprise certificate is available; unsigned pilot mode requires explicit `-AllowUnsignedPilot` and published SHA-256.
- No release passes with a Critical/High unaccepted dependency vulnerability, failed deterministic corpus case, missing coverage-gap expectation, sandbox/network failure, or plaintext canary.

---

## Task P6-T1: Implement six-sheet XLSX export and package security validation

**Files:**
- Create: `src/SecurityReview.Application/Reporting/ExportXlsxCommand.cs`
- Create: `src/SecurityReview.Application/Reporting/ReportExportResult.cs`
- Create: `src/SecurityReview.Application/Reporting/IReportDataReader.cs`
- Create: `src/SecurityReview.Application/Reporting/IXlsxReportExporter.cs`
- Create: `src/SecurityReview.Infrastructure/Reporting/XlsxReportExporter.cs`
- Create: `src/SecurityReview.Infrastructure/Reporting/XlsxCellWriter.cs`
- Create: `src/SecurityReview.Infrastructure/Reporting/XlsxSheetSchemas.cs`
- Create: `src/SecurityReview.Infrastructure/Reporting/XlsxPackageSecurityValidator.cs`
- Create: `tests/SecurityReview.ContractTests/Reporting/XlsxSchemaTests.cs`
- Create: `tests/SecurityReview.ContractTests/Reporting/XlsxSecurityTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Reporting/XlsxExportWorkflowTests.cs`

**Interfaces:**
- Consumes: encrypted scan/query/review projections and user-selected target.
- Produces: `IXlsxReportExporter.ExportAsync`, verified output hash/row counts, and local export diagnostic event.

- [ ] **Step 1: Freeze sheet order and columns in tests**

Use these exact columns:

```text
扫描摘要: 扫描ID,任务状态,有界结论,开始时间UTC,结束时间UTC,资产ID,资产版本,输入摘要,规则包ID,规则包版本,规则包SHA256,本地补充SHA256,有效策略SHA256,客户端版本,解析器指纹,检测器指纹,提示模板版本,LLM模型,文件总数,总字节数,敏感发现数,合规发现数,未覆盖数,缓存复用数,内容转义单元格数,是否旧规则,是否本地补充
敏感内容发现: 扫描ID,资产ID,资产版本,发现组ID,发现位置ID,差异状态,类别ID,类别,风险等级,置信度,完整命中值,上下文,资产类型,相对或虚拟路径,位置类型,精确位置,规则ID,检测器ID,规则版本,LLM状态,LLM分类,LLM置信度,LLM理由,人工状态,例外有效期UTC
资产合规发现: 扫描ID,资产ID,资产版本,发现组ID,发现位置ID,差异状态,资产类型,合规规则ID,结论,风险等级,证据状态,证据引用,相对或虚拟路径,精确位置,人工状态,人工理由
未覆盖内容: 缺口ID,阶段,原因代码,说明代码,格式,相对或虚拟路径,计划字节数,处理字节数,解析器ID,解析器版本,记录时间UTC
文件清单: 文件ID,相对或虚拟路径,数据流,资产类型,格式,大小,内容SHA256,解析器ID,解析器版本,覆盖状态,是否扩展名不一致,是否缓存复用
复核记录: 决策ID,发现组ID,发现位置ID,状态,操作者,记录时间UTC,理由,例外绑定摘要,例外有效期UTC
```

Contract tests assert exact six names/order/headers, every occurrence has a row, group IDs can repeat, summary values match repositories, Partial reports include gaps, and full synthetic value is preserved exactly.

Preflight exact row counts before creating the temp package. Each sheet may contain at most 1,048,575 data rows plus its header. If any projection exceeds the XLSX limit, return `xlsx_row_limit_exceeded` with sheet code/count, create no output, and do not split into extra sheets/files or silently omit rows. This is an explicit XLSX-only product limit that acceptance/documentation must cover.

- [ ] **Step 2: Write formula/external-content attack tests**

Use source strings starting with `=`, `+`, `-`, `@`, tab/CR/LF, DDE formula text, `HYPERLINK`, URL, UNC, XML metacharacters, invalid control characters, bidirectional controls, exactly 32,767 characters, and one character over. Assert every cell has text/inline-string type, zero `<f>` nodes, zero hyperlink/connection/externalLink/macro/OLE/ActiveX/customUI parts/relationships, and no clickable relationship. Invalid XML/bidirectional controls are represented by a documented reversible JSON-string escape with `【JSON转义】` prefix and counted in `内容转义单元格数`. A post-escape value over Excel's limit fails the whole export with `xlsx_cell_limit_exceeded`, deletes the temp file, and never creates continuation rows that would violate one-occurrence/one-row semantics.

- [ ] **Step 3: Run tests and observe missing exporter**

```powershell
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~Xlsx
```

Expected: FAIL because XLSX exporter/types do not exist.

- [ ] **Step 4: Implement safe text-cell streaming**

Use `SpreadsheetDocument.Create` and `OpenXmlWriter` to stream rows. `XlsxCellWriter.WriteText` preserves ordinary source text exactly; when XML-invalid/bidirectional control characters occur **or the original begins with the reserved prefix**, it writes a reversible JSON string with `【JSON转义】` prefix and increments the summary count. This makes decoding unambiguous. Validate the encoded value is at most 32,767 UTF-16 code units without splitting surrogate pairs; otherwise abort atomically. Always emit `CellValues.InlineString` or `CellValues.String`; never set `CellFormula` or hyperlink, and never create hidden continuation rows/columns.

Use a fixed style set for header, date, integer, warning and wrapped text; no template file, macro, named external range, data connection, pivot refresh or calculation chain. Disable auto-fit that would require opening Excel.

Omit custom/core document properties unless required by the package validator. If core properties are emitted, set creator/last-modified-by to the constant `SecurityReviewTool`, use scan UTC rather than workstation/user metadata, and assert the package contains no machine name, absolute source/temp path, printer information, or Windows username outside the intentionally exported `复核记录.操作者` cells.

- [ ] **Step 5: Implement package allowlist validator**

After close, reopen read-only and require: workbook + styles + exactly six worksheet parts + optional shared strings/theme/core/app properties only; exact sheet relationship IDs; zero external relationships; zero macros/OLE/ActiveX/hyperlinks/connections/query tables/custom XML; zero formulas; exact headers/expected row counts; all source columns text typed; no corrupted XML. Reject package over expected size budget or duplicate part URI.

- [ ] **Step 6: Implement atomic export and audit**

Validate target extension `.xlsx`, user confirmation `ContainsCompleteSensitiveValues=true`, and no active existing temp collision. Write `<target>.<128-bit-random>.tmp` in target directory, flush/close/validate/hash, then use atomic `File.Move(temp,target,overwrite:false)`; if target exists return `target_exists` and preserve it. On any failure delete temp best-effort. Record scan ID, UTC, target file SHA-256, row counts and status only; never target full path/value.

- [ ] **Step 7: Run and commit**

```powershell
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~Xlsx
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~XlsxExport
git add src/SecurityReview.Application/Reporting src/SecurityReview.Infrastructure/Reporting tests/SecurityReview.ContractTests/Reporting tests/SecurityReview.IntegrationTests/Reporting
git commit -m "feat: export validated six-sheet XLSX reports"
```

## Task P6-T2: Implement allowlisted diagnostics and redacted support bundle

**Files:**
- Modify: `src/SecurityReview.Application/Diagnostics/DiagnosticCode.cs`
- Modify: `src/SecurityReview.Application/Diagnostics/DiagnosticFields.cs`
- Modify: `src/SecurityReview.Application/Diagnostics/DiagnosticEvent.cs`
- Modify: `src/SecurityReview.Application/Diagnostics/IDiagnosticSink.cs`
- Modify: `src/SecurityReview.Application/Scans/ScanOrchestrator.cs`
- Modify: `src/SecurityReview.Desktop/CompositionRoot.cs`
- Modify: `src/SecurityReview.Infrastructure/Windows/Sandbox/AppContainerWorkerLauncher.cs`
- Modify: `src/SecurityReview.Infrastructure/Persistence/DatabaseHealthCheck.cs`
- Modify: `src/SecurityReview.Infrastructure/Llm/OpenAiSemanticReviewer.cs`
- Modify: `src/SecurityReview.Infrastructure/Reporting/XlsxReportExporter.cs`
- Create: `src/SecurityReview.Infrastructure/Diagnostics/RedactedJsonlDiagnosticSink.cs`
- Create: `src/SecurityReview.Infrastructure/Diagnostics/DiagnosticFieldPolicy.cs`
- Create: `src/SecurityReview.Infrastructure/Diagnostics/DiagnosticBundleExporter.cs`
- Create: `src/SecurityReview.Infrastructure/Diagnostics/SanitizedExceptionFormatter.cs`
- Create: `tests/SecurityReview.UnitTests/Diagnostics/DiagnosticFieldPolicyTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Diagnostics/DiagnosticBundleTests.cs`
- Create: `tests/Corpus/Adversarial/diagnostic-canaries.json`

**Interfaces:**
- Consumes: typed local events from all modules, app/version/OS/rule/parser/model metadata.
- Produces: rotating redacted JSONL and an explicit user-exported ZIP containing allowlisted support evidence only.

- [ ] **Step 1: Write field-policy rejection tests**

Only allow event code, UTC, scan UUID, stage, reason/status code, numeric counts/durations, module/method, OS/app/rule/parser/model/prompt versions, non-reversible endpoint origin fingerprint, and correlation ID. Reject keys containing endpoint URL/host, path, file name, content, value, context, body, request, response, header, token, secret, password, cookie, authorization, SQL/parameter, manifest payload, review reason or stack message.

- [ ] **Step 2: Implement typed events and JSONL sink**

Callers construct `DiagnosticEvent` with enum code and a typed `DiagnosticFields` record, not arbitrary dictionaries. Sink validates fields, writes UTF-8 JSONL atomically, rotates at 10 MiB, keeps five files and 30 days, uses current-user-only ACL, and never logs from worker payload `ToString`. On policy violation drop the field/event and increment an in-memory `diagnostic_policy_violation` counter without including rejected data.

- [ ] **Step 3: Implement sanitized exception formatting**

Keep exception type full name, module, method, HResult/Win32 code, and at most 20 stack frames with source file paths/line numbers/messages/inner data removed. Map known exceptions to stable public codes. Never serialize `Exception.Data` or command line/environment variables.

- [ ] **Step 4: Implement diagnostic bundle allowlist**

ZIP contains only:

```text
summary.json
versions.json
events.jsonl
health/sandbox.json
health/database.json
health/rules.json
health/llm.json
package-manifest.json
```

No DB/WAL/keyring/config credential/rule dictionary/temp/input/report/corpus/screenshot/dump file is eligible. Re-parse every JSON/JSONL entry through the field policy, scan bytes for registered test canaries, generate sorted hashes/size manifest, and write temp→validate→atomic rename. UI warns and requires confirmation.

- [ ] **Step 5: Run canary bundle tests and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Diagnostic
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~DiagnosticBundle
$canaries = Get-Content tests/Corpus/Adversarial/diagnostic-canaries.json -Raw | ConvertFrom-Json
foreach ($canary in $canaries) {
  rg -a -F -- $canary artifacts/diagnostics-test
  if ($LASTEXITCODE -eq 0) { throw "Diagnostic canary leaked." }
  if ($LASTEXITCODE -gt 1) { throw "Canary scan failed with exit code $LASTEXITCODE." }
}
git add src/SecurityReview.Application/Diagnostics src/SecurityReview.Application/Scans/ScanOrchestrator.cs src/SecurityReview.Desktop/CompositionRoot.cs src/SecurityReview.Infrastructure/Diagnostics src/SecurityReview.Infrastructure/Windows/Sandbox/AppContainerWorkerLauncher.cs src/SecurityReview.Infrastructure/Persistence/DatabaseHealthCheck.cs src/SecurityReview.Infrastructure/Llm/OpenAiSemanticReviewer.cs src/SecurityReview.Infrastructure/Reporting/XlsxReportExporter.cs tests/SecurityReview.UnitTests/Diagnostics tests/SecurityReview.IntegrationTests/Diagnostics tests/Corpus/Adversarial/diagnostic-canaries.json
git commit -m "security: export allowlisted redacted diagnostics"
```

## Task P6-T3: Build full end-to-end acceptance corpus and 35-lane trace evidence

**Files:**
- Create: `tests/Acceptance/acceptance-manifest.schema.json`
- Create: `tests/Acceptance/acceptance-manifest.json`
- Create: `tests/SecurityReview.IntegrationTests/Acceptance/AcceptanceScenarioRunner.cs`
- Create: `tests/SecurityReview.IntegrationTests/Acceptance/ProductAcceptanceTests.cs`
- Create: `tools/SecurityReview.CorpusTool/Commands/VerifyAcceptanceCommand.cs`
- Create: `docs/srs/evidence/acceptance-trace-template.md`
- Create: `build/verify-traceability.ps1`

**Interfaces:**
- Consumes: all P0–P6-T2 features, parser/rule/LLM corpora and mock services.
- Produces: machine-readable result for every VT-001–VT-035 and SRS/AC trace evidence.

- [ ] **Step 1: Define acceptance scenario schema and coverage**

Each scenario records ID, linked BRD/REQ/AC/SRS/VT, required OS capability, generated input/rules/LLM behavior/user actions, expected scan/conclusion/findings/locators/gaps/reviews/diff/cache/report/network/diagnostic assertions, max duration/memory and evidence artifacts. The manifest requires every REQ-001–019, AC-001–060, SRS-F-001–019 and VT-001–035 at least once.

- [ ] **Step 2: Implement traceability verifier**

`build/verify-traceability.ps1` extracts IDs from PRD/SRS/acceptance manifest, fails on missing/orphan/duplicate invalid IDs, requires each SRS functional row to point to an executable scenario, and outputs counts only. Expected result:

```text
TRACE PASS: REQ=19 AC=60 SRS-F=19 VT=35
```

- [ ] **Step 3: Implement deterministic acceptance runner**

The runner creates isolated app-data/root/output directories, generates synthetic assets, starts mock HTTPS LLM/network canaries, invokes real Application/Desktop-test host, performs specified user commands, closes all processes, validates DB/caches/logs/report/network and deletes sensitive test output. Normalize UUID/time/paths only where manifest marks them variable; never normalize risk/locator/gap/version/hash behavior.

- [ ] **Step 4: Add scenarios for every major alternate flow**

Include portable no-admin startup; file mutation/stale report; Manifest missing/invalid/unknown; magic mismatch/hidden/system/ADS/reparse; encodings/Office/PDF; Python/JAR/binary; Docker deleted layer/no Docker; no-exec/archive attack/worker crash/encryption; baseline/compliance; rule import/tamper/old rule; deterministic/placeholder/entity/third-party; LLM minimization/injection/invalid/unavailable/no-candidate; exact locators/full values/grouping/bounded conclusion/gaps; review/exception/diff/cache; encryption/retention/local-only; XLSX/formula; progress/cancel/preview; corpus thresholds; no telemetry/exact LLM/diagnostics.

- [ ] **Step 5: Run trace and functional acceptance**

```powershell
pwsh ./build/verify-traceability.ps1
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~ProductAcceptance
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-acceptance --manifest tests/Acceptance/acceptance-manifest.json --output artifacts/acceptance/results.json
```

Expected: trace counts exactly match; functional cross-platform-capable cases pass. Windows security/performance-marked cases execute in P6-T4/T6, not silently skipped.

- [ ] **Step 6: Commit**

```powershell
git add tests/Acceptance tests/SecurityReview.IntegrationTests/Acceptance tools/SecurityReview.CorpusTool/Commands/VerifyAcceptanceCommand.cs docs/srs/evidence/acceptance-trace-template.md build/verify-traceability.ps1
git commit -m "test: trace every requirement to executable acceptance scenarios"
```

## Task P6-T4: Prove performance, responsiveness, cancellation, and reliability

**Files:**
- Create: `tests/Performance/reference-host.json`
- Create: `tests/Performance/generate-large-corpus.ps1`
- Create: `tests/SecurityReview.PerformanceTests/Performance/StartupPerformanceTests.cs`
- Create: `tests/SecurityReview.PerformanceTests/Performance/LargeScanPerformanceTests.cs`
- Create: `tests/SecurityReview.PerformanceTests/Performance/MemoryScalingTests.cs`
- Create: `tests/SecurityReview.PerformanceTests/Reliability/FaultInjectionTests.cs`
- Create: `tests/SecurityReview.PerformanceTests/Ui/UiResponsivenessTests.cs`
- Create: `build/run-performance.ps1`
- Create: `docs/srs/evidence/performance-template.md`

**Interfaces:**
- Consumes: exact published release-like app and generated 10 GB/100k corpus.
- Produces: SRS-NFR-001–015 measurements, reliability fault results, and P95 evidence.

- [ ] **Step 1: Freeze reference host and test controls**

Baseline: Windows 11 24H2 x64 supported build, 8 logical CPU cores, 16 GiB RAM, NVMe SSD with ≥1,000 MB/s sequential read, Defender real-time protection enabled, Balanced power plan, AC power, ≥100 GiB free disk, no debugger. `reference-host.json` records actual CPU/model/build/storage/Defender/power settings and rejects a run below baseline. Additional Windows 10 LTSC runs are compatibility, not the primary performance baseline.

- [ ] **Step 2: Generate deterministic large corpora**

Use seeded generators; do not commit 10 GB output. Corpus A: 100,000 mixed small files totaling 10 GB with known sparse synthetic candidates. Corpus B: 1/5/20 GB streaming files. Corpus C: nested/over-limit/archive bomb metadata. Corpus D: worker crash/hang/OOM/corrupt cases. Write generator version/seed/file hashes/expected counts to manifest.

- [ ] **Step 3: Implement measurements and exact thresholds**

- cold startup: 30 clean launches, window interactive signal P95 ≤5 s;
- idle memory: after 60 s P95 working set ≤300 MiB;
- large local scan: five runs after one warm-up, P95 ≤30 min excluding LLM;
- aggregate main+workers peak private bytes ≤1.5 GiB; worker Job ≤1 GiB;
- streaming: 1/5/20 GB peak growth ≤128 MiB between sizes after buffers stabilize;
- UI input dispatch P95 ≤100 ms and progress interval ≤500 ms;
- cancel: 50 points across stages, no new parser/LLM job after 2 s;
- crash/hang/OOM: current file gap, coordinator alive, remaining files processed;
- deterministic duplicate run: finding/location/gap set identical after normalized task IDs/times.

- [ ] **Step 4: Implement fault injection without production backdoors**

Faults are enabled only in test-host builds through injected interfaces: clock, worker launcher, filesystem, SQLite command interceptor and HTTP handler. Release binaries contain no command/endpoint to crash workers, corrupt DB, bypass sandbox or return fake results. Test: disk full, sharing violation retry, DB busy/corruption/migration failure, power/process kill, cache tamper, rule tamper, export failure, network timeout/redirect and parser faults.

- [ ] **Step 5: Run and record evidence**

```powershell
$env:SECURITY_REVIEW_PERF_HOST = "1"
pwsh tests/Performance/generate-large-corpus.ps1 -Output artifacts/perf-corpus -Seed 20260720
pwsh build/run-performance.ps1 -Corpus artifacts/perf-corpus -Runs 5 -Output artifacts/performance
pwsh ./build/test.ps1 -Lane Performance -RequirePerformanceHost
```

Expected: every threshold passes. Evidence records P50/P95/max, OS/hardware/app/rule/parser/detector versions, corpus hash/seed, commands/exits and raw counter files without content/path values.

- [ ] **Step 6: Commit harness/evidence template, not generated corpus/results**

```powershell
git add tests/Performance tests/SecurityReview.PerformanceTests build/run-performance.ps1 docs/srs/evidence/performance-template.md
git commit -m "test: enforce scan performance and reliability targets"
```

## Task P6-T5: Publish, manifest, SBOM, sign, and verify the portable package

**Files:**
- Create: `build/package.ps1`
- Create: `build/verify-package.ps1`
- Create: `build/generate-sbom.ps1`
- Create: `build/package-file-allowlist.txt`
- Create: `src/SecurityReview.Desktop/Assets/release-manifest.schema.json`
- Create: `docs/operations/release-process.md`
- Create: `tests/SecurityReview.ContractTests/Release/PackageManifestTests.cs`
- Create: `tests/SecurityReview.ContractTests/Release/PackageContentTests.cs`

**Interfaces:**
- Consumes: Release build/tests, trusted signer/rule assets and documentation.
- Produces: `SecurityReviewTool-<version>-win-x64.zip`, release manifest, SPDX SBOM, hashes/signatures and deterministic verification output.

- [ ] **Step 1: Write package allowlist and manifest tests**

Required files: root `SecurityReviewTool.exe`; `worker/SecurityReview.Worker.exe`; their managed/native runtime dependencies; trusted public signers/default signed rule package; prompt/schema/resource files; `README-快速开始.md`; `LICENSES/`; `release-manifest.json`; and `_manifest/spdx_2.2/manifest.spdx.json`. Forbidden: `.pdb`, `.xml` compiler docs, test assemblies, corpora, source, `.git`, workbook source, DB/WAL/keyring/config/credential/log/temp/report, private key/certificate, crash dump, package cache.

Manifest lists version, runtime/SDK, target RID, created UTC, signer mode, and sorted files `{path,size,sha256}` excluding the manifest's own hash. Worker hash must equal the hash trusted by staging/self-test.

- [ ] **Step 2: Implement deterministic self-contained publish**

`package.ps1` runs locked restore/build/tests then:

```powershell
dotnet publish src/SecurityReview.Desktop/SecurityReview.Desktop.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=false -p:PublishTrimmed=false -p:DebugSymbols=false -o artifacts/stage/app
dotnet publish src/SecurityReview.Worker/SecurityReview.Worker.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=false -p:PublishTrimmed=false -p:DebugSymbols=false -o artifacts/stage/worker
```

Copy worker files into `app/worker/`, approved assets/docs/licenses only, normalize timestamps for ZIP reproducibility after signing decisions, and reject any unallowlisted file.

- [ ] **Step 3: Generate dependency, vulnerability, and license evidence**

Run the package checks before signing, but generate the file-hash SBOM only after signing so it describes the bytes actually shipped:

```powershell
dotnet list SecurityReviewTool.sln package --vulnerable --include-transitive | Tee-Object artifacts/release/vulnerabilities.txt
dotnet list SecurityReviewTool.sln package --deprecated | Tee-Object artifacts/release/deprecated.txt
```

Fail on any Critical/High vulnerability without a reviewed exception document containing package/version/CVE, reachability, compensating controls, owner and expiry. Include third-party license notices for every direct/transitive package.

- [ ] **Step 4: Implement optional Authenticode with explicit pilot mode**

`package.ps1` requires either `-SigningCertificateThumbprint <thumbprint>` or `-AllowUnsignedPilot`. Sign Desktop/Worker and signable native binaries with organization timestamp service when available, then verify Windows trust. Never export/copy the private certificate. Broad release script rejects unsigned mode; pilot ZIP/README prominently shows unsigned status and SHA-256 verification instructions.

- [ ] **Step 5: Generate the final SBOM, release manifest, and archive**

After signing, `generate-sbom.ps1` restores the repo-local tool and runs against the final staged bytes:

```powershell
dotnet tool restore
dotnet tool run sbom-tool generate -b artifacts/stage/app -bc . -pn SecurityReviewTool `
  -pv $Version -ps InternalSecurityEngineering -nsb https://security-review-tool.invalid/sbom
```

Then reject reparse points and any path outside `package-file-allowlist.txt`; enumerate ordinary files by normalized ordinal relative path; write schema-valid `release-manifest.json` with the size/SHA-256 of every final file except the manifest itself; and re-check the worker hash used by sandbox preflight. Create the ZIP at a random sibling temp path with ordinal entry order, forward-slash names, fixed entry timestamps, no duplicate/case-colliding names, and optimal compression. Close and reopen it, validate it, atomically rename to `SecurityReviewTool-<version>-win-x64.zip`, and write a `.sha256` sidecar. Failure removes only the temporary archive and never overwrites an existing release.

- [ ] **Step 6: Implement package verifier**

Extract ZIP to a new directory, reject path traversal/duplicate names, compare exact allowlist/manifest sizes/hashes, validate SBOM, trusted rules/signers/prompts/schema hashes, Authenticode mode, PE architecture x64, no PDB/forbidden/canary strings, no writable app-data files, and launch `SecurityReviewTool.exe --health-check --no-ui` as non-admin. Verify health JSON contains app/worker/runtime/rules/sandbox codes only.

- [ ] **Step 7: Build twice and compare reproducibility**

With the same source/version/SDK/package lock, build twice and require application assemblies/assets/rules/prompts/schemas to have identical hashes before Authenticode. Authenticode timestamps and Microsoft SBOM creation metadata can make final binary/SBOM/manifest/ZIP hashes variable; compare their validated semantic content with an explicit allowlist limited to signature/timestamp/SBOM document-identity fields, then verify each final signature and manifest independently. Any other file/content difference fails. Record both deterministic and expected-volatile sets in release evidence; do not claim the timestamped final ZIP is byte-for-byte reproducible.

- [ ] **Step 8: Run and commit**

```powershell
pwsh build/package.ps1 -Version 1.0.0-pilot.1 -AllowUnsignedPilot
pwsh build/verify-package.ps1 -Package artifacts/release/SecurityReviewTool-1.0.0-pilot.1-win-x64.zip -RequireUnsignedPilotWarning
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~Package
git add build src/SecurityReview.Desktop/Assets/release-manifest.schema.json docs/operations/release-process.md tests/SecurityReview.ContractTests/Release
git commit -m "build: produce verified portable Windows release package"
```

## Task P6-T6: Execute clean-VM matrix, pilot readiness, and final evidence

**Files:**
- Create: `docs/operations/quick-start.md`
- Create: `docs/operations/coverage-and-conclusions.md`
- Create: `docs/operations/llm-configuration.md`
- Create: `docs/operations/rule-import.md`
- Create: `docs/operations/xlsx-report.md`
- Create: `docs/operations/diagnostics-and-support.md`
- Create: `docs/operations/uninstall-and-clear-data.md`
- Create: `docs/operations/pilot-runbook.md`
- Create: `docs/operations/release-checklist.md`
- Create: `build/run-clean-vm-validation.ps1`
- Create: `docs/srs/evidence/v1-release-evidence.md`

**Interfaces:**
- Consumes: exact P6-T5 ZIP and all machine-readable evidence.
- Produces: release/pilot decision package, user/support documentation, and final VT-001–035 evidence.

- [ ] **Step 1: Provision the minimum compatibility matrix**

Use clean x64 VMs with no installed .NET/Desktop runtime, Docker, Java, Python or Office:

1. Windows 11 24H2 supported build, standard non-admin user;
2. Windows 10 Enterprise LTSC 2021 (21H2) supported build, standard non-admin user;
3. every additional edition/build found in the actual internal fleet and claimed by release notes.

Snapshot before run. Test from a user-writable extracted directory and a long/spaced/Chinese path. Do not disable Defender, SmartScreen or enterprise policy; record their state.

- [ ] **Step 2: Automate clean-VM validation**

`run-clean-vm-validation.ps1` verifies ZIP/hash/signature, extracts, checks no admin prompt/service/scheduled task/system registry change, starts under 5 seconds, passes sandbox health, runs synthetic file/directory/Docker scans, valid/invalid rules, mock intranet LLM, cancel/review/rescan/XLSX/diagnostics/retention/clear-data, then inspects process/network/filesystem/registry deltas.

Use `pktmon`/Windows firewall log plus local canaries. Allowed network is DNS/TLS only for the configured LLM origin during semantic work; no startup/scan/crash/shutdown telemetry. Worker must have zero connections including loopback.

- [ ] **Step 3: Validate documentation against a fresh user**

Quick start explains download/hash/signature, extract/start, select final asset, coverage status, review and XLSX warning. Coverage document lists all supported/partial/unsupported formats and exact bounded conclusion. XLSX guide defines six sheets, full-value warning, reversible control-character representation, 32,767-character/1,048,575-data-row limits, and atomic failure behavior. LLM guide requires HTTPS/credential handling. Rule guide imports signed ZIP only. Diagnostics guide states allowlist. Uninstall guide distinguishes program directory, LocalAppData clear and AppContainer profile cleanup.

Have a pilot user who did not implement the product complete the synthetic workflow using only docs; record confusion as issue IDs and resolve release-blocking gaps before sign-off.

- [ ] **Step 4: Run every required release gate on the exact package**

```powershell
pwsh ./build/verify-traceability.ps1
pwsh ./build/test.ps1 -Lane Unit,Contract,ParserCorpus,Integration -RequireCorpus
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity
$env:SECURITY_REVIEW_PERF_HOST = "1"
pwsh ./build/test.ps1 -Lane Performance -RequirePerformanceHost
pwsh ./build/verify-package.ps1 -Package artifacts/release/SecurityReviewTool-1.0.0-win-x64.zip -RequireSignature
pwsh ./build/run-clean-vm-validation.ps1 -Package artifacts/release/SecurityReviewTool-1.0.0-win-x64.zip -Output artifacts/clean-vm
```

Expected: every command exits 0; no unexpected skipped test; 19 REQ, 60 AC, 19 SRS-F, 35 VT traced; deterministic high-risk corpus 100%; semantic recall ≥95% on fixed annotated model/prompt set with false-positive rate reported; expected coverage gap 100%; package/network/plaintext scans clean.

- [ ] **Step 5: Compile final evidence without sensitive data**

`v1-release-evidence.md` records package hash/signature, source revision, SDK/runtime/package/rule/parser/detector/prompt/model IDs, OS builds, commands/exits/test counts, performance P50/P95, semantic recall/false-positive metrics, SBOM/vulnerability status, trace counts, clean-VM outcomes, known documented coverage limits, pilot participants by internal role (not personal data), and release approver roles.

- [ ] **Step 6: Apply release decision rules**

Release only if all gates pass and product/security/quality owners approve. Any sandbox escape/network leak/plaintext leak/missed deterministic high-risk sample/formula link/missing expected gap is a hard block. Performance/semantic metric miss is also a block unless the upstream requirement is formally changed; do not turn a failed threshold into a narrative exception in this plan.

- [ ] **Step 7: Commit documentation and evidence template**

```powershell
git add docs/operations build/run-clean-vm-validation.ps1 docs/srs/evidence/v1-release-evidence.md
git commit -m "docs: finalize pilot operations and release evidence"
```

P6 and V1 are complete only after the exact distributed ZIP, not merely a developer build, passes the clean-VM, security, corpus, performance, XLSX, diagnostics, SBOM and traceability gates.
