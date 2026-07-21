# Performance Evidence — Security Review Tool

> **Template**: fill after each `run-performance.ps1` execution.
> **Schema**: one section per NFR, with raw data + P50/P95/max columns.
> **Commit policy**: commit this template; never commit raw corpus files or generated outputs.

---

## Run Metadata

| Field | Value |
|---|---|
| Run ID | `<uuid>` |
| Timestamp (UTC) | `<ISO 8601>` |
| Git revision | `<git rev-parse HEAD>` |
| Build configuration | `Release` |
| Corpus seed | `20260720` |
| Corpus hash (SHA-256) | `<64 hex>` |
| Corpus size (files / GiB) | `<N> / <N>` |
| Rule pack version | `<version>` |
| Rule pack fingerprint | `<sha256>` |
| Parser versions | `<adapter:version per line>` |
| Detector versions | `<detector:version per line>` |
| LLM model | `<model>` (or `none` if excluded) |
| LLM endpoint fingerprint | `<sha256 of uri template>` |
| Prompt version | `<version>` |

---

## Host Environment

| Field | Value |
|---|---|
| OS edition | `<e.g. Windows 11 Enterprise>` |
| OS build | `<e.g. 26100.xxxx>` |
| CPU model | `<e.g. Intel Core i7-13700H>` |
| Logical cores | `<N>` |
| Total RAM (GiB) | `<N>` |
| Storage type | `<NVMe / SATA SSD / HDD>` |
| Sequential read (MB/s) | `<N>` |
| Free disk (GiB) | `<N>` |
| Defender real-time | `<enabled / disabled>` |
| Power plan | `<Balanced / High Performance / ...>` |
| AC power | `<yes / no>` |
| Debugger attached | `<no / yes>` |
| Free memory at start (GiB) | `<N>` |
| Baseline tier | `<primary / compatibility>` |

---

## SRS-NFR-001 — Cold Startup

**Target**: P95 ≤ 5 s (30 cold launches, window interactive signal).

| Run | Launch # | Duration (ms) | Interactive? | Notes |
|---|---|---|---|---|
| 1 | 1–30 | `<comma-separated>` | `<yes/no per>` |  |
| ... | ... | ... | ... |  |

| Metric | Value |
|---|---|
| P50 (ms) | `<N>` |
| P95 (ms) | `<N>` |
| Max (ms) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |
| Command | `dotnet test --filter StartupPerformance` |
| Exit code | `<N>` |

---

## SRS-NFR-002 — Idle Memory

**Target**: working set ≤ 300 MiB (60 s after startup).

| Run | Sample time (s) | Working set (MiB) | Private bytes (MiB) | Notes |
|---|---|---|---|---|
| 1 | 60 | `<N>` | `<N>` |  |
| ... | ... | ... | ... |  |

| Metric | Value |
|---|---|
| P50 (MiB) | `<N>` |
| P95 (MiB) | `<N>` |
| Max (MiB) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-003 — Scan Peak Memory

**Target**: main + workers peak ≤ 1.5 GiB private bytes; worker Job ≤ 1 GiB.

| Run | Main peak (MiB) | Workers sum peak (MiB) | Total peak (MiB) | Worker Job peak (MiB) | Notes |
|---|---|---|---|---|---|
| 1 | `<N>` | `<N>` | `<N>` | `<N>` |  |
| ... | ... | ... | ... | ... |  |

| Metric | Value |
|---|---|
| P50 total (MiB) | `<N>` |
| P95 total (MiB) | `<N>` |
| Max total (MiB) | `<N>` |
| P50 worker Job (MiB) | `<N>` |
| P95 worker Job (MiB) | `<N>` |
| Max worker Job (MiB) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-004 — Large Local Scan Throughput

**Target**: P95 ≤ 30 min (10 GB / 100k files, excluding LLM time, 5 runs after 1 warm-up).

| Run | Duration (s) | Files processed | Files skipped | Coverage % | LLM excluded? | Notes |
|---|---|---|---|---|---|---|
| 1 (warm-up) | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |
| 2 | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |
| 3 | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |
| 4 | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |
| 5 | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |
| 6 | `<N>` | `<N>` | `<N>` | `<N>` | yes |  |

| Metric | Value |
|---|---|
| P50 (s) | `<N>` |
| P95 (s) | `<N>` |
| Max (s) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-005 — Streaming Memory Growth

**Target**: peak growth ≤ 128 MiB across 1 / 5 / 20 GB files after buffers stabilize.

| File size (GiB) | Peak working set (MiB) | Growth from 1 GiB baseline (MiB) | Notes |
|---|---|---|---|
| 1 | `<N>` | — |  |
| 5 | `<N>` | `<N>` |  |
| 20 | `<N>` | `<N>` |  |

| Metric | Value |
|---|---|
| Max growth 1→5 (MiB) | `<N>` |
| Max growth 1→20 (MiB) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-006 — Cancellation Responsiveness

**Target**: no new parser/LLM job dispatched after 2 s from cancel signal.

| Cancel point | Time to last dispatch (ms) | New jobs after 2 s? | Notes |
|---|---|---|---|
| `<stage 1..50>` | `<N>` | `<0 / count>` |  |
| ... | ... | ... |  |

| Metric | Value |
|---|---|
| P50 cancel latency (ms) | `<N>` |
| P95 cancel latency (ms) | `<N>` |
| Max cancel latency (ms) | `<N>` |
| Cancels with jobs after 2 s | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-007 — UI Responsiveness

**Target**: input dispatch P95 ≤ 100 ms; progress refresh ≤ 500 ms.

| Run | Event type | P50 (ms) | P95 (ms) | Max (ms) | Notes |
|---|---|---|---|---|---|
| 1 | input dispatch | `<N>` | `<N>` | `<N>` |  |
| 1 | progress refresh | `<N>` | `<N>` | `<N>` |  |
| ... | ... | ... | ... | ... |  |

| Metric | Value |
|---|---|
| Input P95 (ms) | `<N>` |
| Progress interval P95 (ms) | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-008 — Crash Isolation

**Target**: each malicious sample at most affects its job; coordinator alive; remaining files processed.

| Fault type | Worker affected? | Coordinator alive? | Remaining files processed? | Gap recorded? | Notes |
|---|---|---|---|---|---|
| worker crash | `<yes/no>` | `<yes>` | `<yes/no>` | `<yes/no>` |  |
| worker hang | `<yes/no>` | `<yes>` | `<yes/no>` | `<yes/no>` |  |
| worker OOM | `<yes/no>` | `<yes>` | `<yes/no>` | `<yes/no>` |  |
| corrupt file | `<yes/no>` | `<yes>` | `<yes/no>` | `<yes/no>` |  |

| Metric | Value |
|---|---|
| Total fault cases | `<N>` |
| Coordinator survived | `<N>` |
| Remaining files processed | `<N>` |
| Gaps recorded | `<N>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## SRS-NFR-015 — Deterministic Reproducibility

**Target**: identical finding/location/gap set across two runs with same inputs (normalized task IDs / timestamps).

| Run | Total findings | Finding set hash | Coverage gaps | Gap set hash | Notes |
|---|---|---|---|---|---|
| A | `<N>` | `<sha256>` | `<N>` | `<sha256>` |  |
| B | `<N>` | `<sha256>` | `<N>` | `<sha256>` |  |

| Metric | Value |
|---|---|
| Finding set match? | `<yes / no>` |
| Gap set match? | `<yes / no>` |
| Pass/Fail | `<PASS / FAIL>` |

---

## Fault Injection Results

| Fault | Injected via | Observed behavior | Expected behavior | Pass/Fail |
|---|---|---|---|---|
| disk full | filesystem fake | `<observed>` | `<expected>` |  |
| sharing violation retry | filesystem fake |  |  |  |
| DB busy | sqlite interceptor |  |  |  |
| DB corruption | sqlite interceptor |  |  |  |
| DB migration failure | sqlite interceptor |  |  |  |
| power/process kill | worker launcher fake |  |  |  |
| cache tamper | cache fake |  |  |  |
| rule tamper | rule store fake |  |  |  |
| export failure | filesystem fake |  |  |  |
| network timeout | http handler fake |  |  |  |
| network redirect | http handler fake |  |  |  |
| parser fault | worker launcher fake |  |  |  |

---

## Summary

| NFR | Target | Measured P95 | Pass/Fail |
|---|---|---|---|
| SRS-NFR-001 | ≤ 5 s | `<N> s` |  |
| SRS-NFR-002 | ≤ 300 MiB | `<N> MiB` |  |
| SRS-NFR-003 | ≤ 1.5 GiB | `<N> GiB` |  |
| SRS-NFR-004 | ≤ 30 min | `<N> min` |  |
| SRS-NFR-005 | ≤ 128 MiB | `<N> MiB` |  |
| SRS-NFR-006 | ≤ 2 s | `<N> s` |  |
| SRS-NFR-007 (input) | ≤ 100 ms | `<N> ms` |  |
| SRS-NFR-007 (progress) | ≤ 500 ms | `<N> ms` |  |
| SRS-NFR-008 | coordinator survives | `<yes/no>` |  |
| SRS-NFR-015 | deterministic | `<yes/no>` |  |

**Overall Pass/Fail**: `<PASS / FAIL>`

---

## Evidence Artifacts

| Artifact | Path | SHA-256 |
|---|---|---|
| Raw counters | `artifacts/performance/counters/` | — |
| TRX results | `artifacts/performance/*.trx` | `<sha256>` |
| Host snapshot | `artifacts/performance/host-snapshot.json` | `<sha256>` |
| Corpus manifest | `artifacts/perf-corpus/manifest.json` | `<sha256>` |
| Diagnostic log | `artifacts/performance/diagnostic.jsonl` | `<sha256>` |
