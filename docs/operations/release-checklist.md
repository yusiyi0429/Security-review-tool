# Release Checklist — SecurityReviewTool v1.0.0

This checklist defines every required gate for the v1.0.0 release. Every item
must pass or have a documented, approved exception **before** the release is
declared complete. Partial or skipped items block the release.

## Approver Roles

| Role | Responsibility | Hard-Block Authority |
|------|---------------|---------------------|
| **Product Owner** | Signs off on feature completeness, acceptance criteria, and pilot feedback. | Scope regression, missing AC coverage. |
| **Security Owner** | Signs off on sandbox isolation, network behavior, plaintext-secret handling, and crypto implementation. | Sandbox escape, plaintext leak, network leak. |
| **Quality Owner** | Signs off on test results, corpus coverage, traceability, and clean-VM outcomes. | Failing test lane, missed deterministic corpus, broken traceability. |
| **Release Engineer** | Executes the package build, signature, and reproducibility checks. | Broken build, non-reproducible package, failed package verification. |

All four roles must approve. No role may approve their own work — the
Security Owner cannot also be the Release Engineer, and the Quality Owner
cannot also be the Product Owner.

---

## Gate 1: Source and Build Integrity

- [ ] **1.1** Source is at a tagged commit (`v1.0.0`) with a clean working
  tree (`git status --porcelain` is empty).
- [ ] **1.2** Locked restore succeeds (`dotnet restore --locked-mode`).
- [ ] **1.3** All projects build in Release configuration.
- [ ] **1.4** No compilation warnings remain (treat-warnings-as-errors
  policy).
- [ ] **1.5** `Directory.Packages.props` versions match the lock file exactly.

## Gate 2: Test Lanes

- [ ] **2.1** Unit lane: all pass, 0 skipped (or skipped are documented and
  approved).
- [ ] **2.2** Contract lane: all pass, 0 skipped.
- [ ] **2.3** Parser Corpus lane: all pass, 0 skipped.
- [ ] **2.4** Integration lane: all pass, 0 skipped.
- [ ] **2.5** Windows Security lane: all pass, 0 skipped, must run on genuine
  Windows with `SECURITY_REVIEW_RUN_WINDOWS_SECURITY=1`.
- [ ] **2.6** Performance lane: all pass, must run on a dedicated perf host
  with `SECURITY_REVIEW_PERF_HOST=1`.

```powershell
pwsh ./build/test.ps1 -Lane Unit,Contract,ParserCorpus,Integration -RequireCorpus
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity
$env:SECURITY_REVIEW_PERF_HOST = "1"
pwsh ./build/test.ps1 -Lane Performance -RequirePerformanceHost
```

## Gate 3: Traceability

- [ ] **3.1** `pwsh ./build/verify-traceability.ps1` exits 0.
- [ ] **3.2** 19 REQ IDs present and linked (REQ-001 through REQ-019).
- [ ] **3.3** 60 AC IDs present and linked (AC-001 through AC-060).
- [ ] **3.4** 19 SRS-F IDs present and linked (SRS-F-001 through SRS-F-019).
- [ ] **3.5** 35 VT IDs present and linked (VT-001 through VT-035).
- [ ] **3.6** Every SRS-F has ≥1 acceptance scenario.
- [ ] **3.7** Every VT has ≥1 acceptance scenario.
- [ ] **3.8** No orphan, duplicate, or malformed IDs.

## Gate 4: Deterministic Corpus

- [ ] **4.1** Deterministic high-risk corpus coverage: **100%**.
  Any missed sample is a hard block — no exceptions.
- [ ] **4.2** Expected presence/absence confirmed for all corpus entries.
- [ ] **4.3** No unauthorized placeholder suppression.
- [ ] **4.4** Corpus manifest hashes verified against extracted content.

## Gate 5: Semantic Review

- [ ] **5.1** Semantic recall ≥ **95%** on the fixed annotated model/prompt
  set.
- [ ] **5.2** False-positive rate is recorded and within acceptable bounds
  (threshold defined by Product Owner before measurement).
- [ ] **5.3** Model and prompt versions are recorded and frozen for the
  release measurement.

> If semantic recall < 95% or FPR exceeds the defined threshold, this is a
> block unless the upstream requirement (REQ-level) is formally changed. Do
> not turn a failed threshold into a narrative exception.

## Gate 6: Package Integrity

- [ ] **6.1** Package build succeeds.
- [ ] **6.2** `pwsh ./build/verify-package.ps1 -Package <zip> -RequireSignature`
  exits 0.
- [ ] **6.3** Allowlist compliance: every file in ZIP matches
  `build/package-file-allowlist.txt`.
- [ ] **6.4** No `.pdb`, `.xml` doc, test, corpus, source, workbook, `.db`,
  `.sqlite`, WAL, SHM, keyring, credential, or config files in ZIP.
- [ ] **6.5** SHA-256 sidecar published and verified.
- [ ] **6.6** Authenticode signature valid (production) or unsigned-pilot
  warning displayed (pilot).

## Gate 7: Reproducibility

- [ ] **7.1** Two independent builds produce ZIPs with identical file hashes
  (excluding timestamps, SPDX document IDs, and signature bytes).
- [ ] **7.2** Differing fields documented: `created_utc`, SPDX namespace,
  signature/timestamp.
- [ ] **7.3** No other file content differences.

## Gate 8: Clean-VM Validation

- [ ] **8.1** Windows 11 24H2 VM: full clean-VM script passes.
- [ ] **8.2** Windows 11 x64 (supported builds only) VM: full clean-VM script passes.
- [ ] **8.3** Long/spaced/Chinese extraction path tested on at least one VM.
- [ ] **8.4** Defender and SmartScreen ON during validation.
- [ ] **8.5** No admin prompt, service, or scheduled task.
- [ ] **8.6** Startup ≤ 5 seconds.
- [ ] **8.7** Sandbox health check passes.
- [ ] **8.8** Zero worker network connections (including loopback).
- [ ] **8.9** Zero startup telemetry.
- [ ] **8.10** pktmon/firewall log confirms DNS+TLS only to configured LLM
  host; no other connections.

## Gate 9: Vulnerability and SBOM

- [ ] **9.1** `dotnet list package --vulnerable --include-transitive` reveals
  no Critical or High CVEs without reviewed exceptions.
- [ ] **9.2** Every exception has: CVE ID, reachability analysis,
  compensating controls, owner, expiry date.
- [ ] **9.3** SBOM is valid SPDX 2.2 JSON.
- [ ] **9.4** SBOM includes all NuGet dependencies (transitive).
- [ ] **9.5** No deprecated packages without reviewed replacement plan.

## Gate 10: Documentation and Pilot

- [ ] **10.1** All 7 operations docs exist and are reviewed: quick-start,
  coverage, LLM, rules, XLSX, diagnostics, uninstall.
- [ ] **10.2** Pilot runbook is complete.
- [ ] **10.3** A non-developer pilot user completed the synthetic workflow
  using only the documentation.
- [ ] **10.4** Pilot confusion/issues are recorded and resolved.
- [ ] **10.5** Release-blocking documentation gaps are closed.

## Hard-Block Criteria

The following conditions **always** block the release. No exception, no
narrative override, no risk-acceptance bypass:

| Condition | Detection | Owner |
|-----------|-----------|-------|
| **Sandbox escape** — worker process reads/writes outside the sandbox, spawns unsandboxed child, or accesses network | WindowsSecurity lane, clean-VM validation | Security Owner |
| **Plaintext secret leak** — credential, API key, or encryption key written to log, temp file, or XLSX in recoverable form | Security audit, diagnostics review | Security Owner |
| **Network leak** — any network connection (including loopback) from worker process, or telemetry/usage data sent from main process | clean-VM pktmon, firewall log | Security Owner |
| **Missed deterministic high-risk sample** — a corpus sample with a known-critical match is not detected | Corpus lane | Quality Owner |
| **Formula link** — XLSX contains a formula that could resolve to sensitive content or external reference | XLSX audit, package scan | Security Owner |
| **Missing expected coverage gap** — a format or condition that must produce a gap silently succeeds or fails to record the gap | Corpus lane, integration lane | Quality Owner |
| **Broken traceability** — any REQ, AC, SRS-F, or VT missing, orphaned, or unlinked | verify-traceability.ps1 | Quality Owner |
| **Failing test lane** — any lane exits non-zero | test.ps1 | Quality Owner |
| **Non-reproducible package** — file hashes differ between builds beyond allowed fields | Reproducibility gate | Release Engineer |

## Soft-Block Criteria

These conditions block the release unless an approved exception is documented:

| Condition | Exception Format |
|-----------|-----------------|
| Performance P50/P95 exceed baseline | Product Owner approval with documented rationale |
| Semantic recall < 95% (but not catastrophic) | REQ-level scope change |
| False-positive rate > defined threshold | Product Owner acceptance |
| Windows 11 x64 (supported builds only) behavior differs from baseline | Security Owner assessment of fail-closed behavior |
| Documentation gap found by pilot | Resolution before sign-off |

## Release Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Product Owner | | | |
| Security Owner | | | |
| Quality Owner | | | |
| Release Engineer | | | |

---

All gates must pass and all four roles must sign before the ZIP is published.
