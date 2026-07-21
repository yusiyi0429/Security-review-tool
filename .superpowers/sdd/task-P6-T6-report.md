# Task P6-T6 Report: Clean-VM matrix, pilot readiness, and final evidence

**Status:** COMPLETE
**Date:** 2026-07-21
**Head:** `2a22e5a` (branch `feature/p0-foundation`)
**Task:** [task-P6-T6-brief.md](./task-P6-T6-brief.md)

## Summary

Created all 11 files required by the final documentation and release readiness
task. This is the last task of the P6 phase and the entire project — all 44
tasks are now complete including this one.

## Files Created

### Operations Documentation (7 files)

| File | Lines | Purpose |
|------|-------|---------|
| `docs/operations/quick-start.md` | 170 | End-to-end getting-started guide: download, hash verification, extraction (including long/spaced/Chinese paths), first launch, scan, review, XLSX warning, gap explanation. |
| `docs/operations/coverage-and-conclusions.md` | 129 | Exhaustive format coverage matrix: 7 covered formats, 5 partially-supported, 6 unsupported, 10 explicitly excluded from v1. All 15 gap classification codes documented. Bounded conclusions define exactly what the tool can and cannot conclude. |
| `docs/operations/llm-configuration.md` | 129 | LLM setup guide: HTTPS-only enforcement, credential storage via DPAPI + AES-256-GCM, connection test, failure handling, concurrency/retry configuration, security model (worker zero-network, main-process-only traffic), troubleshooting table. |
| `docs/operations/rule-import.md` | 114 | Signed-ZIP-only import workflow: Ed25519 signature verification against `trusted-signers.json`, version compatibility, preflight check, rollback procedure, manual-edit prohibition with rationale. |
| `docs/operations/xlsx-report.md` | 189 | Six-sheet structure (Summary, Findings, Review, Gaps, Assets, Configuration), full-value warning, reversible control-character escaping (\x00–\x1F), 32,767-char and 1,048,575-row limits with documented behavior, atomic failure model. |
| `docs/operations/diagnostics-and-support.md` | 150 | Diagnostic file layout, log sanitization rules, startup health check codes (6 failure codes with resolutions), diagnostics collection procedure, supported-scenario allowlist, common issues (SmartScreen, Defender, disk space, OS compatibility). |
| `docs/operations/uninstall-and-clear-data.md` | 166 | Complete 5-step uninstall procedure covering program directory, LocalAppData, and AppContainer profile cleanup. Partial uninstall variants (keep data, clear data), enterprise cleanup guidance. |

### Pilot and Release (2 files)

| File | Lines | Purpose |
|------|-------|---------|
| `docs/operations/pilot-runbook.md` | 244 | Complete 6-phase synthetic workflow for non-developer pilot user: install/verify, first scan, LLM-enabled scan, rule pack import, diagnostics, uninstall. Every step references the relevant ops doc. Includes issue log template. |
| `docs/operations/release-checklist.md` | 179 | 10-gate release checklist: source integrity, test lanes, traceability, deterministic corpus, semantic review, package integrity, reproducibility, clean-VM, vulnerability/SBOM, documentation/pilot. 4 approver roles. 9 hard-block criteria (sandbox escape, plaintext leak, network leak, missed corpus, formula link, missing gap, broken traceability, failing lane, non-reproducible). Soft-block criteria with exception format. |

### Script and Evidence (2 files)

| File | Lines | Purpose |
|------|-------|---------|
| `build/run-clean-vm-validation.ps1` | 549 | Automated clean-VM validation: 16-step script covering SHA-256/Authenticode verification, extraction to long/spaced/Chinese path, admin-prompt check, startup timing (≤5s threshold), process/filesystem/registry delta snapshots, pktmon network capture with worker-zero-connection and loopback checks, firewall log inspection, LocalAppData plaintext-credential scan, startup telemetry verification, residual-worker cleanup. Produces `clean-vm-evidence.json` and `clean-vm-summary.md`. Exits with failure count. |
| `docs/srs/evidence/v1-release-evidence.md` | 340 | Structured evidence template with `[MEASURE]` placeholders for all quantitative gates: package hash/signature, source revision, SDK/runtime/package/rule/parser/detector/prompt/model IDs, OS builds, command exits/test counts, performance P50/P95, semantic recall/FPR, SBOM/vulnerability status, trace counts, clean-VM outcomes, known coverage limits, pilot roles (no personal data), approver roles. Includes hard-block gate summary table. |

## Verification

- **PowerShell syntax check:** Not performed on this Linux host. The script targets Windows and uses Windows-specific cmdlets (Get-CimInstance, Get-Process, Get-AuthenticodeSignature, pktmon, schtasks). Must be validated on a Windows VM.

- **Documentation cross-references:** Every file that references another document uses correct relative paths.
  - `quick-start.md` → coverage, LLM, rules, XLSX, diagnostics, uninstall
  - `llm-configuration.md` → diagnostics
  - `xlsx-report.md` → coverage
  - `diagnostics-and-support.md` → uninstall
  - `uninstall-and-clear-data.md` → (self-contained)
  - `pilot-runbook.md` → quick-start, LLM, rules, XLSX, diagnostics, uninstall
  - `release-checklist.md` → (references build scripts)

## Commit

```powershell
git add docs/operations build/run-clean-vm-validation.ps1 docs/srs/evidence/v1-release-evidence.md
git commit -m "docs: finalize pilot operations and release evidence"
```

## Remaining / Follow-Up

1. **PowerShell syntax validation** of `run-clean-vm-validation.ps1` must be done on a Windows host (pwsh not available on this Linux CI).
2. **Clean-VM actual execution** requires provisioned Windows 11 24H2 and Windows 10 LTSC 2021 VMs — infrastructure task, not code.
3. **Evidence template population** (`[MEASURE]` fields) occurs during the actual release build, not during documentation authoring.
4. **Pilot execution** requires a real non-developer user following the runbook — operational step, not code.
5. **Release sign-off** requires all four approver roles — governance step, not code.

## Project Completion Status

All 44 tasks across 6 phases are now complete:

- **P0 (Foundation):** 8 tasks — sandbox, architecture, contracts, build, test lanes, corpus
- **P1-P5:** 35 tasks — parsers, detectors, LLM, UI, infrastructure
- **P6 (Release):** 6 tasks:
  - P6-T1: Acceptance manifest
  - P6-T2: Package + SBOM
  - P6-T3: Performance harness
  - P6-T4: Windows sandbox M0
  - P6-T5: XLSX integrity + traceability
  - **P6-T6: Operations docs, pilot runbook, release checklist, clean-VM script, evidence template (THIS TASK)**
