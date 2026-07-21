# v1.0.0 Release Evidence

> **Template — fill in measured values before publishing the release.**
> Fields marked `[MEASURE]` must be populated from actual release builds.
> Fields marked `[APPROVER]` must be filled by the named role.

---

## Package Identity

| Field | Value |
|-------|-------|
| Package file | `SecurityReviewTool-1.0.0-win-x64.zip` |
| SHA-256 | `[MEASURE]` |
| Authenticode signer | `[MEASURE]` (or `unsigned_pilot` for pilot) |
| Signer certificate subject | `[MEASURE]` |
| Signer certificate thumbprint | `[MEASURE]` |
| Package size (bytes) | `[MEASURE]` |
| Manifest schema version | 1 |
| Manifest file count | `[MEASURE]` |
| SBOM format | SPDX 2.2 |
| SBOM document namespace | `[MEASURE]` |

---

## Source and Build

| Field | Value |
|-------|-------|
| Git revision | `[MEASURE]` (full SHA) |
| Git tag | `v1.0.0` |
| Build host OS | `[MEASURE]` |
| .NET SDK version | `[MEASURE]` (from `global.json`) |
| .NET runtime version | `[MEASURE]` (self-contained, from publish output) |
| Target RID | `win-x64` |
| Configuration | `Release` |
| Self-contained | `true` |
| PublishTrimmed | `false` |
| DebugSymbols | `false` |

---

## Package Content Versions

| Component | Version / ID | SHA-256 |
|-----------|-------------|---------|
| SecurityReview.Desktop | 1.0.0 | `[MEASURE]` |
| SecurityReview.Worker | 1.0.0 | `[MEASURE]` |
| SecurityReview.Application | 1.0.0 | `[MEASURE]` |
| SecurityReview.Domain | 1.0.0 | `[MEASURE]` |
| SecurityReview.Infrastructure | 1.0.0 | `[MEASURE]` |
| SecurityReview.ParserContracts | 1.0.0 | `[MEASURE]` |
| SecurityReview.Parsers | 1.0.0 | `[MEASURE]` |
| SecurityReview.RulePack | 1.0.0 | `[MEASURE]` |
| Baseline rule pack version | `[MEASURE]` | `[MEASURE]` |
| Baseline rule pack signer key ID | `[MEASURE]` | — |
| Rule workbook version | `[MEASURE]` | `[MEASURE]` |

---

## Parser Identity

| Parser | Version | SHA-256 (assembly) |
|--------|---------|-------------------|
| ZipParser | 1.0.0 | `[MEASURE]` |
| TarParser | 1.0.0 | `[MEASURE]` |
| GZipParser | 1.0.0 | `[MEASURE]` |
| TextParser | 1.0.0 | `[MEASURE]` |
| PdfParser (PdfPig 0.1.14) | 1.0.0 | `[MEASURE]` |
| OpenXmlParser (DocumentFormat.OpenXml) | 1.0.0 | `[MEASURE]` |
| ModelParser | 1.0.0 | `[MEASURE]` |

---

## Detector Identity

| Detector | Config ID | SHA-256 (config) |
|----------|-----------|-------------------|
| `[MEASURE]` | `[MEASURE]` | `[MEASURE]` |

*(List every detector shipped in the baseline rule pack.)*

---

## Semantic Review Configuration

| Field | Value |
|-------|-------|
| LLM provider | Internal (OpenAI-compatible) |
| Model name | `[MEASURE]` |
| Prompt version | `[MEASURE]` |
| Prompt SHA-256 | `[MEASURE]` |
| Max concurrent requests | `[MEASURE]` |
| Annotation set version | `[MEASURE]` |
| Annotation set SHA-256 | `[MEASURE]` |

---

## OS Build Matrix — Clean-VM Validation

| OS | Build | Result | Evidence Path |
|----|-------|--------|---------------|
| Windows 11 24H2 x64 | `[MEASURE]` | `[PASS/FAIL]` | `artifacts/clean-vm/win11-24h2/clean-vm-evidence.json` |
| Windows 11 x64 (supported builds only) | `[MEASURE]` | `[PASS/FAIL]` | `artifacts/clean-vm/win11-supported/clean-vm-evidence.json` |
| *(additional fleet builds)* | `[MEASURE]` | `[PASS/FAIL]` | `[path]` |

### Clean-VM Checklist (per OS)

| Check | Win11 24H2 | Win11 Supported |
|-------|-----------|-----------------|
| ZIP SHA-256 verified | `[✓/✗]` | `[✓/✗]` |
| Extraction to long/spaced/Chinese path | `[✓/✗]` | `[✓/✗]` |
| No admin prompt | `[✓/✗]` | `[✓/✗]` |
| No service installed | `[✓/✗]` | `[✓/✗]` |
| No scheduled task created | `[✓/✗]` | `[✓/✗]` |
| No system registry change | `[✓/✗]` | `[✓/✗]` |
| Startup ≤ 5 seconds | `[✓/✗]` | `[✓/✗]` |
| Sandbox health check pass | `[✓/✗]` | `[✓/✗]` |
| Synthetic scan pass | `[✓/✗]` | `[✓/✗]` |
| Review/Confirm/Dismiss/Exception | `[✓/✗]` | `[✓/✗]` |
| Rescan pass | `[✓/✗]` | `[✓/✗]` |
| XLSX export (6 sheets) | `[✓/✗]` | `[✓/✗]` |
| Diagnostics collection | `[✓/✗]` | `[✓/✗]` |
| Clear data / reinitialize | `[✓/✗]` | `[✓/✗]` |
| Zero worker network (incl. loopback) | `[✓/✗]` | `[✓/✗]` |
| Zero startup telemetry | `[✓/✗]` | `[✓/✗]` |
| Defender ON during test | `[✓/✗]` | `[✓/✗]` |
| SmartScreen ON during test | `[✓/✗]` | `[✓/✗]` |
| No residual processes after exit | `[✓/✗]` | `[✓/✗]` |

---

## Test Results

### Command Summary

```powershell
# All commands must exit 0
pwsh ./build/verify-traceability.ps1                             # Exit: [MEASURE]
pwsh ./build/test.ps1 -Lane Unit,Contract,ParserCorpus,Integration -RequireCorpus  # Exit: [MEASURE]
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity  # Exit: [MEASURE]
pwsh ./build/test.ps1 -Lane Performance -RequirePerformanceHost     # Exit: [MEASURE]
pwsh ./build/verify-package.ps1 -Package <zip> -RequireSignature    # Exit: [MEASURE]
pwsh ./build/run-clean-vm-validation.ps1 -Package <zip> -Output artifacts/clean-vm  # Exit: [MEASURE]
```

### Test Counts

| Lane | Total | Passed | Failed | Skipped |
|------|-------|--------|--------|---------|
| Unit | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |
| Contract | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |
| ParserCorpus | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |
| Integration | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |
| WindowsSecurity | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |
| Performance | `[MEASURE]` | `[MEASURE]` | 0 | `[MEASURE]` |

---

## Traceability

| ID Type | Expected | Found | Coverage |
|---------|----------|-------|----------|
| REQ | 19 (REQ-001–019) | `[MEASURE]` | `[MEASURE]`% |
| AC | 60 (AC-001–060) | `[MEASURE]` | `[MEASURE]`% |
| SRS-F | 19 (SRS-F-001–019) | `[MEASURE]` | `[MEASURE]`% |
| VT | 35 (VT-001–035) | `[MEASURE]` | `[MEASURE]`% |

### SRS-F Trace (abbreviated — full trace in `verify-traceability.ps1` output)

| SRS-F | Description | Scenario Coverage |
|-------|-------------|-------------------|
| SRS-F-001 | File inventory and format detection | `[MEASURE]` |
| SRS-F-002 | Worker sandbox isolation (AppContainer) | `[MEASURE]` |
| SRS-F-003 | Job Object resource limits | `[MEASURE]` |
| SRS-F-004 | Pipe protocol (versioned, length-prefixed) | `[MEASURE]` |
| SRS-F-005 | Deterministic detector engine | `[MEASURE]` |
| SRS-F-006 | LLM semantic review integration | `[MEASURE]` |
| SRS-F-007 | Coverage gap recording (all categories) | `[MEASURE]` |
| SRS-F-008 | Encrypted SQLite history | `[MEASURE]` |
| SRS-F-009 | DPAPI credential protection | `[MEASURE]` |
| SRS-F-010 | XLSX report (six sheets) | `[MEASURE]` |
| SRS-F-011 | Rule pack import (signed ZIP) | `[MEASURE]` |
| SRS-F-012 | Review workflow (confirm/dismiss/exception) | `[MEASURE]` |
| SRS-F-013 | Preflight health check (fail-closed) | `[MEASURE]` |
| SRS-F-014 | Portable deployment (no install) | `[MEASURE]` |
| SRS-F-015 | Uninstall and clear data | `[MEASURE]` |
| SRS-F-016 | Diagnostics collection (sanitized) | `[MEASURE]` |
| SRS-F-017 | No network telemetry | `[MEASURE]` |
| SRS-F-018 | No external internet dependency | `[MEASURE]` |
| SRS-F-019 | Long/spaced/Chinese path support | `[MEASURE]` |

### VT Trace (abbreviated)

| VT | Description | Scenario Coverage |
|----|-------------|-------------------|
| VT-001–035 | *(see acceptance manifest for full mapping)* | `[MEASURE]` |

---

## Deterministic Corpus

| Metric | Value |
|--------|-------|
| Corpus test cases | `[MEASURE]` |
| High-risk coverage | `[MEASURE]`% (target: 100%) |
| Expected presence confirmed | `[MEASURE]` / `[MEASURE]` |
| Expected absence confirmed | `[MEASURE]` / `[MEASURE]` |
| Unauthorized placeholder suppression | `[MEASURE]` (target: 0) |
| Detector errors | `[MEASURE]` (target: 0) |

---

## Semantic Review Metrics

| Metric | Value | Threshold |
|--------|-------|-----------|
| Semantic recall | `[MEASURE]`% | ≥ 95% |
| False-positive rate | `[MEASURE]`% | ≤ `[DEFINED BY PRODUCT OWNER]`% |
| Model version | `[MEASURE]` | — |
| Prompt version | `[MEASURE]` | — |
| Annotation set size | `[MEASURE]` regions | — |
| Annotation set version | `[MEASURE]` | — |

---

## Performance Metrics

| Metric | P50 | P95 | P99 | Baseline |
|--------|-----|-----|-----|----------|
| Cold startup (seconds) | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` |
| Warm startup (seconds) | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | — |
| File inventory (files/sec) | `[MEASURE]` | — | — | `[MEASURE]` |
| Worker task latency (ms) | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` |
| Memory — idle (MB) | `[MEASURE]` | — | — | `[MEASURE]` |
| Memory — scan peak (MB) | `[MEASURE]` | — | — | `[MEASURE]` |
| XLSX export (rows/sec) | `[MEASURE]` | — | — | — |

**Reference host:** `[MEASURE]` (CPU, RAM, disk type, OS build)
**Performance host:** `[MEASURE]` (dedicated machine used for measurements)

---

## Vulnerability and SBOM Status

| Check | Status |
|-------|--------|
| Critical CVEs | `[MEASURE]` |
| High CVEs | `[MEASURE]` |
| Medium CVEs | `[MEASURE]` |
| Low CVEs | `[MEASURE]` |
| CVEs with reviewed exceptions | `[MEASURE]` |
| Deprecated packages | `[MEASURE]` |
| Deprecated with replacement plan | `[MEASURE]` |
| SBOM SPDX 2.2 valid | `[✓/✗]` |
| SBOM transitive dependencies included | `[✓/✗]` |

### CVE Exception Register

| CVE ID | Package | Version | Reachability | Compensating Control | Owner | Expiry |
|--------|---------|---------|-------------|---------------------|-------|--------|
| `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` | `[MEASURE]` |

---

## Known Coverage Limits

These limits are documented in [Coverage and Conclusions](../operations/coverage-and-conclusions.md)
and are accepted for v1.0.0:

1. **Unsupported formats**: PE, ELF, Java Class, raw binary, empty files.
2. **Legacy Office**: `.doc`, `.xls`, `.ppt` — no parser.
3. **Encrypted files**: detected as gap; no decryption.
4. **Archive limits**: 100K entries, depth 5, 4 GiB/entry, 50 GiB total.
5. **PDF limits**: 10 MiB text/page, 1M characters/page, ≤64 MiB attachments.
6. **XLSX cell limit**: 32,767 characters (truncated with marker).
7. **XLSX row limit**: 1,048,575 data rows (split across sheets).
8. **Model metadata only**: no tensor-scanning for secrets.
9. **Single-user only**: no concurrent scans; no local RBAC.
10. **Windows x64 only**: Windows 11 24H2 and Windows 11 x64 (supported builds only).

---

## Pilot Participants

List roles only — no personal names, usernames, or contact information.

| Role | Internal Role | Completed Runbook | Issues Reported |
|------|--------------|-------------------|-----------------|
| Pilot User 1 | `[ROLE]` | `[✓/✗]` | `[MEASURE]` |
| Pilot User 2 | `[ROLE]` | `[✓/✗]` | `[MEASURE]` |
| Pilot User 3 | `[ROLE]` | `[✓/✗]` | `[MEASURE]` |

### Pilot Issue Summary

| Issue ID | Step | Severity | Resolution |
|----------|------|----------|------------|
| `[MEASURE]` | `[MEASURE]` | `[cosmetic/confusing/blocking]` | `[MEASURE]` |

---

## Release Approver Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| **Product Owner** | `[APPROVER]` | `[DATE]` | |
| **Security Owner** | `[APPROVER]` | `[DATE]` | |
| **Quality Owner** | `[APPROVER]` | `[DATE]` | |
| **Release Engineer** | `[APPROVER]` | `[DATE]` | |

All four roles must sign. No role may approve their own work.

---

## Hard-Block Gate Summary

| Gate | Status | Evidence |
|------|--------|----------|
| Sandbox isolation (no escape) | `[PASS/FAIL]` | WindowsSecurity lane, clean-VM |
| Plaintext leak (none) | `[PASS/FAIL]` | Security audit, clean-VM |
| Network leak (worker: 0 connections) | `[PASS/FAIL]` | clean-VM pktmon |
| Startup telemetry (none) | `[PASS/FAIL]` | clean-VM pktmon |
| Deterministic corpus (100%) | `[PASS/FAIL]` | Corpus lane |
| Formula links in XLSX (none) | `[PASS/FAIL]` | Package scan |
| Missing expected gaps (none) | `[PASS/FAIL]` | Corpus + Integration lanes |
| Traceability (all IDs linked) | `[PASS/FAIL]` | verify-traceability.ps1 |
| All test lanes pass | `[PASS/FAIL]` | test.ps1 |
| Reproducible package | `[PASS/FAIL]` | Package gate |
| Vulnerability scan (no Critical/High unaddressed) | `[PASS/FAIL]` | SBOM, vulnerability report |
| Pilot documentation review | `[PASS/FAIL]` | Pilot issue log |

---

## Release Decision

| Decision | Date | Rationale |
|----------|------|-----------|
| `[GO / NO-GO]` | `[DATE]` | `[MEASURE]` |

**All hard-block gates must pass. The release is complete only after the exact distributed ZIP passes clean-VM, security, corpus, performance, XLSX, diagnostics, SBOM, and traceability gates.**
