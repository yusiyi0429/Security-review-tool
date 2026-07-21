# Acceptance Traceability Structure

| Property | Value |
| --- | --- |
| Doc version | 0.1 |
| Date | 2026-07-21 |
| Based on | `tests/Acceptance/acceptance-manifest.json` (v1.0, 35 scenarios) |
| Upstream | PRD (`docs/prd/prd-security-asset-content-review-tool.md`), SRS (`docs/srs/srs-security-asset-content-review-tool.md`) |

## 1. Overview

**Acceptance tracing** is the process of linking every business objective down through requirements, acceptance criteria, software specifications, and verification tests — ending in executable acceptance scenarios. It exists to answer one question at any point in the delivery lifecycle: _does a passing test suite actually prove the product meets the business need?_

The traceability chain for this project is:

```text
BRD-OBJ (Business Objectives)
  → REQ (Product Requirements, 19 items)
    → AC (Acceptance Criteria, 60 items)
      → SRS-F (Software Requirements, 19 functional + 16 NFR)
        → VT (Verification Tests, 35 items)
          → ACC (Acceptance Scenarios, 35 items)
```

Each ACC scenario in `acceptance-manifest.json` declares its place in this chain via `linkedReqs`, `linkedAcs`, `linkedSrsFs`, and `linkedVts` fields, providing machine-readable bidirectional traceability from deployment evidence back to business goals.

The acceptance manifest is the single source of truth for the product's release gate: all 35 ACC scenarios must pass on a supported Windows build before a version can ship.

## 2. Traceability Chain

### 2.1 Layer Definitions

| Layer | ID format | Count | Defined in |
| --- | --- | --- | --- |
| BRD-OBJ | `BRD-OBJ-001`..`003` | 3 | PRD §1.1 |
| REQ | `REQ-001`..`019` | 19 | PRD §4.2 |
| AC | `AC-001`..`060` | 60 | PRD §4.4 |
| SRS-F | `SRS-F-001`..`019` | 19 | SRS §4 |
| SRS-NFR | `SRS-NFR-001`..`016` | 16 | SRS §14 |
| VT | `VT-001`..`035` | 35 | SRS §17.2 |
| ACC | `ACC-001`..`035` | 35 | `tests/Acceptance/acceptance-manifest.json` |

### 2.2 How the Chain Works

1. **BRD-OBJ** defines _why_ the product exists (3 business objectives from the PRD).
2. Each **REQ** is a product-level requirement linked to one or more BRD-OBJs.
3. Each **AC** is a testable acceptance criterion for a specific user story (US), linked to one REQ.
4. Each **SRS-F** is a software-level functional specification that implements one REQ; every REQ has exactly one primary SRS-F.
5. Each **VT** describes a verification test case with a primary assertion and measurement method.
6. Each **ACC** is a machine-executable scenario that validates one VT against specific assertions (`expectedScan`, `expectedFindings`, `expectedGaps`, etc.).

The mapping is **not** 1:1 at every level: a single ACC scenario often validates multiple ACs that share the same verification test. For example, ACC-003 maps to three ACs (AC-002, AC-003, AC-004) because file mutation, retry, and unstable-marking are verified in one integrated scenario.

## 3. Manifest Structure

### 3.1 Files

| File | Purpose |
| --- | --- |
| `tests/Acceptance/acceptance-manifest.json` | The executable manifest: 35 ACC scenarios with expected assertions. |
| `tests/Acceptance/acceptance-manifest.schema.json` | JSON Schema (draft-07) that validates the manifest structure. |

### 3.2 Scenario Schema

Each `AcceptanceScenario` entry contains:

| Field | Required | Description |
| --- | --- | --- |
| `id` | Yes | Unique identifier, pattern `ACC-\d{3}` |
| `description` | Yes | Human-readable scenario description |
| `linkedReqs` | Yes | Array of `REQ-001`..`019` |
| `linkedAcs` | Yes | Array of `AC-001`..`060` |
| `linkedSrsFs` | Yes | Array of `SRS-F-001`..`019` |
| `linkedVts` | Yes | Array of `VT-001`..`035` |
| `requiredOsCapability` | Yes | `"any"`, `"windows-sandbox"`, or `"windows-gui"` |
| `maxDurationMs` | Yes | Maximum duration in milliseconds |
| `maxMemoryMb` | Yes | Maximum memory in megabytes |
| `variableFields` | No | Fields to normalize during comparison: `uuid`, `timestamp`, `tempPath` |
| `syntheticInput` | No | Description of synthetic assets to generate |
| `expectedScan` | No | Expected scan outcome (status, min/max files, chunks, gaps) |
| `expectedConclusion` | No | Expected bounded conclusion assertions |
| `expectedFindings` | No | Expected finding patterns (value, severity, kind) |
| `expectedLocators` | No | Expected locator types and positions |
| `expectedGaps` | No | Expected coverage gap reasons |
| `expectedReviews` | No | Expected review/exceptions behaviour |
| `expectedDiff` | No | Expected diff on rescan (new, disappeared, persistent) |
| `expectedCache` | No | Expected cache behaviour (reuse, invalidation) |
| `expectedReport` | No | Expected XLSX report assertions (sheet count, formula injection) |
| `expectedNetwork` | No | Expected network behaviour (no telemetry, LLM-only) |
| `expectedDiagnostic` | No | Expected diagnostic log assertions |

### 3.3 OS Capability Semantics

| `requiredOsCapability` | Meaning | Count |
| --- | --- | --- |
| `"any"` | Runs on any platform (Linux, macOS, Windows via mock sandbox) | 25 |
| `"windows-sandbox"` | Requires AppContainer sandbox; skipped on non-Windows | 8 |
| `"windows-gui"` | Requires WPF GUI interaction; skipped on non-Windows | 2 |

## 4. How to Add a New Scenario

1. **Identify the gap.** Determine which VT (or new VT) needs a new ACC scenario, and which REQ/AC/SRS-F it links to.

2. **Add to the manifest.** Open `tests/Acceptance/acceptance-manifest.json` and insert a new entry in the `scenarios` array:

   ```json
   {
     "id": "ACC-036",
     "description": "Short description of what this scenario validates.",
     "linkedReqs": ["REQ-XXX"],
     "linkedAcs": ["AC-XXX"],
     "linkedSrsFs": ["SRS-F-XXX"],
     "linkedVts": ["VT-XXX"],
     "requiredOsCapability": "any",
     "maxDurationMs": 30000,
     "maxMemoryMb": 512,
     "variableFields": ["uuid", "timestamp", "tempPath"],
     "syntheticInput": {
       "description": "Describe the synthetic input to generate.",
       "fileCount": 2,
       "useMockLlm": true,
       "mockLlmOutcome": "confirmed"
     },
     "expectedScan": {
       "status": "Completed",
       "minFindings": 1
     },
     "expectedFindings": [
       {
         "valuePattern": "expected-pattern",
         "kind": "SensitiveContent"
       }
     ]
   }
   ```

3. **Validate the schema.** Ensure the new entry passes the JSON Schema:

   ```powershell
   # Manual schema validation (using a JSON Schema validator)
   # The build pipeline validates this automatically.
   ```

4. **Implement the verification logic** in `SecurityReview.IntegrationTests` or `SecurityReview.CorpusTool` to:
   - Generate the `syntheticInput` described
   - Execute the scan
   - Assert against every `expected*` block

5. **Run the verification** (see §5) and confirm the new scenario passes.

6. **Update this document** — add the new ACC row to the coverage matrix in §7.

## 5. How to Run Verification

### 5.1 Traceability Integrity Check

Validates that every REQ, AC, SRS-F, and VT is linked, and no orphans exist:

```powershell
pwsh ./build/verify-traceability.ps1
```

### 5.2 Product Acceptance Tests

Runs integration tests tagged with `ProductAcceptance`:

```powershell
dotnet test tests/SecurityReview.IntegrationTests --filter ProductAcceptance
```

### 5.3 Corpus-Based Acceptance Verification

Runs acceptance scenarios from the manifest against real or synthetic corpus:

```powershell
dotnet run --project tools/SecurityReview.CorpusTool -- verify-acceptance --manifest tests/Acceptance/acceptance-manifest.json --output artifacts/acceptance/results.json
```

> **Note:** The `verify-acceptance` command is planned but not yet implemented in the CorpusTool. The current CorpusTool supports `scan-smoke`, `verify-parser-corpus`, and `verify-rule-corpus`. The `verify-acceptance` command is the target interface for the full 35-scenario gate.

### 5.4 Windows-Specific Verification

Scenarios tagged `"requiredOsCapability": "windows-sandbox"` or `"windows-gui"` are automatically skipped on non-Windows platforms. To run the full gate on Windows (from WSL2 or directly):

```powershell
# Run the Windows security lane (AppContainer, pipe, ADS, DPAPI, network isolation)
pwsh ./build/test.ps1 -Lane WindowsSecurity -RequireWindowsSecurity

# Or from WSL2, use the cross-build lane script:
./build/windows-lane.sh
```

## 6. Interpreting Results

Each ACC scenario produces one of three outcomes:

### PASS
All `expected*` assertions are satisfied. The scenario's assertions matched the actual scan output after normalizing `variableFields` (UUIDs, timestamps, temp paths).

### SKIP
The runtime environment does not meet `requiredOsCapability`. For example:
- `windows-sandbox` scenarios skip on Linux/macOS because AppContainer is not available.
- `windows-gui` scenarios skip on headless Windows or non-Windows.

A skip is **not** a failure — it means the scenario was not evaluated and must be verified separately on a Windows host.

### FAIL
One or more assertions did not match:
- `expectedScan.status` mismatch — the scan did not reach the expected terminal state.
- `expectedFindings` — a required finding pattern was missing, or its kind/severity was wrong.
- `expectedGaps` — an expected coverage gap was not recorded, or an unexpected gap appeared.
- `expectedLocators` — the locator type or position was incorrect.
- `expectedDiff` / `expectedCache` / `expectedReport` / `expectedNetwork` / `expectedDiagnostic` — the corresponding behaviour assertion failed.

**Important:** Any FAIL on a scenario linked to a P0 REQ blocks the release. A SKIP on a Windows-only scenario means the Windows gate has not been exercised for that release.

## 7. Coverage Matrix

The following table maps every acceptance scenario to its primary verification test and linked requirements.

### 7.1 Full Matrix

| ACC | Primary VT | Linked REQ(s) | Linked AC(s) | Requires | Key Assertion |
| --- | --- | --- | --- | --- | --- |
| ACC-001 | VT-001 | REQ-001 | AC-001 | Windows | Portable startup in sandbox, bounded conclusion |
| ACC-002 | VT-002 | REQ-001 | AC-001 | Windows | Cold start ≤5 s on 0 files |
| ACC-003 | VT-003 | REQ-002 | AC-002, AC-003, AC-004 | Any | Input summary, mutation → Partial, diff detection |
| ACC-004 | VT-004 | REQ-003 | AC-005, AC-006 | Windows | Manifest read + missing file handling |
| ACC-005 | VT-005 | REQ-004 | AC-007 | Any | Magic/extension mismatch → SensitiveContent |
| ACC-006 | VT-006 | REQ-004 | AC-008, AC-009 | Windows | Hidden files + ADS content → AccessDenied gaps |
| ACC-007 | VT-007 | REQ-005 | AC-010, AC-011 | Any | UTF-8/UTF-16/GBK multi-encoding |
| ACC-008 | VT-008 | REQ-005 | AC-012 | Any | Office + PDF boundary parsing |
| ACC-009 | VT-009 | REQ-006 | AC-013, AC-014, AC-015 | Any | Python/JAR/binary — TextLocator, NestedLocator, ByteLocator |
| ACC-010 | VT-010 | REQ-007 | AC-016, AC-017 | Any | Docker/OCI layout — min 1 chunk |
| ACC-011 | VT-011 | REQ-008 | AC-018 | Windows | Script-like files not executed |
| ACC-012 | VT-012 | REQ-008 | AC-018 | Windows | Network denial — only LLM endpoint contacted |
| ACC-013 | VT-013 | REQ-008 | AC-019 | Any | Archive bomb/decompression limits |
| ACC-014 | VT-014 | REQ-008 | AC-020, AC-021 | Any | Encrypted + corrupt files → Partial with Encrypted gap |
| ACC-015 | VT-015 | REQ-009 | AC-022, AC-023, AC-024 | Any | 8-class baseline — SensitiveContent + AssetCompliance |
| ACC-016 | VT-016 | REQ-010 | AC-025, AC-026, AC-027 | Any | Rule pack import + tamper invalidates cache |
| ACC-017 | VT-017 | REQ-011 | AC-028, AC-029, AC-030, AC-031 | Any | Multi-detector finds SECRET pattern |
| ACC-018 | VT-018 | REQ-012 | AC-032 | Any | LLM minimization — no sensitive data in requests |
| ACC-019 | VT-019 | REQ-012 | AC-033 | Any | LLM prompt injection detected |
| ACC-020 | VT-020 | REQ-012 | AC-034, AC-035 | Any | LLM unavailable → Partial with LlmUnresolved gap |
| ACC-021 | VT-021 | REQ-013 | AC-036, AC-037, AC-038, AC-039, AC-040 | Any | TextLocator with line numbers + apikey pattern |
| ACC-022 | VT-022 | REQ-014 | AC-041, AC-042 | Any | Review + exception bound to scan version |
| ACC-023 | VT-023 | REQ-014 | AC-043, AC-044 | Any | Diff (new/disappeared/persistent) + cache reuse + invalidation |
| ACC-024 | VT-024 | REQ-015 | AC-045 | Windows | DPAPI-based encryption of scan artifacts |
| ACC-025 | VT-025 | REQ-015 | AC-046, AC-047 | Windows | Retention local-only, no exfiltration |
| ACC-026 | VT-026 | REQ-016 | AC-048, AC-049 | Any | XLSX export — 6 sheets present |
| ACC-027 | VT-027 | REQ-016 | AC-050 | Any | Formula injection prevention — no formulas, no external links |
| ACC-028 | VT-028 | REQ-017 | AC-051, AC-052 | Windows | Progress + cancel via GUI — Cancelled status |
| ACC-029 | VT-029 | REQ-017 | AC-053, AC-054 | Windows | Preview + external open from GUI |
| ACC-030 | VT-030 | REQ-018 | AC-055 | Any | Deterministic regression — SensitiveContent at High severity |
| ACC-031 | VT-031 | REQ-018 | AC-056 | Any | Semantic recall ≥95% — requires semantic review |
| ACC-032 | VT-032 | REQ-018 | AC-057 | Any | Gap coverage 100% — zero coverage gaps on healthy files |
| ACC-033 | VT-033 | REQ-019 | AC-058 | Any | No telemetry — no asset content or sensitive values in logs |
| ACC-034 | VT-034 | REQ-019 | AC-059 | Any | LLM network only — only LLM endpoint contacted |
| ACC-035 | VT-035 | REQ-019 | AC-060 | Any | Diagnostic log redaction — no asset/LM body/sensitive in logs |

### 7.2 Windows-Only Scenarios

These 10 scenarios require a Windows environment and produce **skip** on Linux/macOS:

| ACC | Description | Capability Required |
| --- | --- | --- |
| ACC-001 | Portable startup in Windows sandbox | `windows-sandbox` |
| ACC-002 | Cold start timing on Windows | `windows-sandbox` |
| ACC-004 | Manifest read + missing with Windows sandbox | `windows-sandbox` |
| ACC-006 | Hidden + ADS content (NTFS-specific) | `windows-sandbox` |
| ACC-011 | No execution of script-like files in sandbox | `windows-sandbox` |
| ACC-012 | Network denial via AppContainer | `windows-sandbox` |
| ACC-024 | DPAPI-based encryption | `windows-sandbox` |
| ACC-025 | Retention + local-only verification | `windows-sandbox` |
| ACC-028 | Progress + cancel via WPF GUI | `windows-gui` |
| ACC-029 | Preview + external open via WPF GUI | `windows-gui` |

### 7.3 Cross-Platform Scenarios

The remaining 25 scenarios (ACC-003, ACC-005, ACC-007 through ACC-010, ACC-013 through ACC-023, ACC-026, ACC-027, ACC-030 through ACC-035) have `"requiredOsCapability": "any"` and are expected to pass on all platforms. On Linux, these run against a mock/emulated sandbox layer rather than the real AppContainer.

## 8. Windows vs Linux

### 8.1 Architectural Constraint

The Security Review Tool is designed as a **Windows-native** application. Its security model depends on:

- **AppContainer** (Windows sandbox capability — no equivalent on Linux)
- **Job Objects** (resource limits per worker process tree)
- **NTFS Alternate Data Streams** (ADS)
- **DPAPI** (CurrentUser data protection)
- **WPF** (Windows-only GUI framework)
- **Named Pipe ACLs** (SID-based access control)

### 8.2 What Runs Where

| Platform | Scenarios Run | Expected Passes | Notes |
| --- | --- | --- | --- |
| **Windows 11 x64** | All 35 | 35 | Full gate |
| **Windows 10 Enterprise/IoT LTSC** | All 35 | 35 (subject to .NET 10 support matrix) | Requires supported edition |
| **Linux (WSL2/dev)** | 25 cross-platform | 25 | Windows-only scenarios auto-skip |
| **macOS** | 25 cross-platform | 25 | Windows-only scenarios auto-skip |

### 8.3 Skip Logic

When a scenario's `requiredOsCapability` is `"windows-sandbox"` or `"windows-gui"` and the host is not Windows, the test runner must:

1. Log the skip with the reason: `"requiredOsCapability: windows-sandbox — not available on <platform>"`
2. Record the skip in `results.json` under the scenario ID
3. **Not** treat the skip as a failure — the scenario must still be verified on a Windows host before release

The CI pipeline enforces that Windows-only scenarios **cannot** report `PASS` when running under `SECURITY_REVIEW_RUN_WINDOWS_SECURITY != 1`. This prevents a skipped scenario from being mistaken for a passing one.

### 8.4 Running Windows Scenarios from Linux/WSL2

Use `build/windows-lane.sh` to cross-build and execute the Windows security lane on the Windows host:

```bash
./build/windows-lane.sh
```

This script:
1. Publishes `SecurityReview.Worker` and `SecurityReview.WindowsSecurityTests` as self-contained `win-x64` binaries
2. Stages them on the Windows host via `/mnt/c`
3. Invokes the test runner via `powershell.exe`
4. Collects evidence (OS build info, worker hash, lane log) into `artifacts/windows-security/`

## 9. Traceability Verification Checklist

Before any release, confirm:

- [ ] `pwsh ./build/verify-traceability.ps1` exits 0
- [ ] All 25 cross-platform ACC scenarios pass on at least one Linux/macOS CI runner
- [ ] All 10 Windows-only ACC scenarios pass on a supported Windows build
- [ ] `acceptance-manifest.json` schema validation passes
- [ ] All 19 REQ, 60 AC, 19 SRS-F, and 35 VT IDs are accounted for in the manifest
- [ ] No scenario has an empty `linkedReqs`, `linkedAcs`, `linkedSrsFs`, or `linkedVts` array
- [ ] `results.json` from the acceptance run is archived with the release evidence

## 10. References

- PRD: `docs/prd/prd-security-asset-content-review-tool.md`
- SRS: `docs/srs/srs-security-asset-content-review-tool.md`
- SRS Walkthrough: `docs/srs/srs-walkthrough.md`
- ADR: `docs/adr/0001-windows-native-modular-monolith-and-sandboxed-parser-workers.md`
- Manifest: `tests/Acceptance/acceptance-manifest.json`
- Manifest Schema: `tests/Acceptance/acceptance-manifest.schema.json`
- Build scripts: `build/build.ps1`, `build/test.ps1`, `build/windows-lane.sh`
