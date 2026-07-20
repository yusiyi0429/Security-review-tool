# M0 evidence: Windows parser sandbox isolation (P0)

**Verdict: PASS on the tested host.** All nine sandbox isolation invariants plus the
fail-closed preflight self-test pass with real Windows execution. This document is
deliberately sanitized: no usernames, absolute paths, pipe names, file contents, or
network addresses.

## Environment

- OS: Microsoft Windows 11 Home China, build **26200** (64-bit, x64)
- .NET SDK used to build/publish: **10.0.302** (linux-x64 controller, cross-published win-x64 self-contained)
- Test host runtime: self-contained .NET 10 (no shared framework on host)
- Worker build: `SecurityReview.Worker.exe` probe build (`SECURITY_REVIEW_SANDBOX_PROBE`), SHA-256
  `4fc383e2444ee601e3b222dc78d13b2d6e47b9e1c0c870aa9bbdf8820285c21d`
  (identical digest recomputed on the publish output and on the staged Windows copy)
- AppContainer profile name: `Company.SecurityReviewTool.Parser.V1`
- AppContainer SID: `S-1-15-2-887602955-2522038634-2498173890-859054622-3566658199-1865181384-2127197090`
- Worker staging integrity: `worker-manifest.json` (SHA-256 over all 207 staged files),
  verified before any ACL grant and before launch

## Sandbox configuration under test

- AppContainer with **zero capabilities**; worker staging directory granted read/execute
  to the AppContainer SID only (never the scan root or the tool data directory)
- Scan-wide Job: active-process limit **4**, job memory **1,073,741,824 bytes (1 GiB)**,
  kill-on-close
- Per-worker child Job (nested under the scan Job): active-process limit **1**,
  process memory **402,653,184 bytes (384 MiB)** ordinary / **1,073,741,824 bytes (1 GiB)**
  OCI-exclusive, die-on-unhandled-exception, kill-on-close
- Named pipe: SDDL DACL with exactly the current-user SID and the AppContainer SID,
  random 128-bit name, byte mode, single instance, overlapped, 1 MiB buffers,
  remote clients rejected
- Protocol: length-prefixed JSON, 1 MiB frame cap, stateful session validator
  (Hello nonce + worker build SHA-256 handshake, sequence discipline, digest-based
  idempotent retransmission)

## Test execution

- Command: `build/windows-lane.sh` (publishes probe worker + `WindowsSecurityTests`
  self-contained, stages to a Windows temp directory, runs the xUnit v3 test exe with
  `SECURITY_REVIEW_RUN_WINDOWS_SECURITY=1`)
- Result: **Total 24, Errors 0, Failed 0, Skipped 0**, lane exit code **0**,
  zero stray worker processes after the run
- Application preflight tests (Linux, in-process xUnit runner): **14/14 pass**

## Boundary assertion results (all PASS)

1. Worker reads the duplicated handle (canary label only) but cannot read the sibling path.
2. Duplicated handle is read-only; a write attempt is denied.
3. Worker cannot connect to loopback TCP, host LAN TCP, DNS (UDP/53 and name
   resolution), or a documentation-only external address — every attempt denied or
   dropped although listeners/DNS would answer an unsandboxed process.
4. Worker token: `TokenIsAppContainer` true, exact expected AppContainer SID, zero
   capabilities; the capability enumeration is proven non-vacuous by locating the
   Everyone group through the same stride-correct parse.
5. Per-worker Job (active-process 1) denies child-process spawn; the scan Job admits
   the 4-worker pool and rejects a 5th process (fail-closed, no unsandboxed fallback).
6. 512 MiB allocation terminates the ordinary worker (classified `ParserMemory`);
   the OCI-exclusive worker holds the same allocation under its 1 GiB ceiling.
7. A 2-second deadline terminates a hanging worker (classified `ParserTimeout`).
8. Closing a worker's child Job kills only that worker; closing the scan Job kills all.
9. Second pipe client rejected; pipe SDDL contains no broad ACEs (Everyone / Users /
   Authenticated Users / all-AppPackages all absent).
10. Handshake spoof (wrong nonce, wrong build hash) rejects the launch; skipped or
    conflicting-duplicate sequences and an oversized frame terminate the session and
    job (classified `ParserProtocolMismatch`); exact retransmission is ignored
    idempotently.
11. Worker cannot use the handle after the job/process is disposed; the parent process
    remains alive and fully functional after a worker crash (exit code 3,
    classified `ParserCrash`).
12. Tampered worker manifest fails closed before any ACL grant.
13. Cached sandbox self-test: passes with a bound fingerprint (worker SHA-256, OS
    build, AppContainer SID, manifest, policy); success is reused only while the
    fingerprint matches and is at most 24 hours old; a failure is never cached as
    success and never triggers an unsandboxed fallback launch.
14. Scan preflight aggregates stable error codes (`root_invalid`, `baseline_inactive`,
    `app_data_not_writable`, `database_unhealthy`, `sandbox_unavailable`) and exposes
    no "continue anyway" path.

## Known platform notes

- On build 26200, `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT` requires
  `STARTUPINFOEX.cb = sizeof(STARTUPINFOEX)`.
- The OS asynchronously reclaims unused AppContainer profiles; the launcher verifies
  the profile mapping at ensure time and re-creates + retries once on the
  profile-missing error. Proven by forced profile deletion followed by a green lane.

## Outstanding evidence

- **Windows 10 LTSC 2021 evidence is still outstanding.** Nested Job Object behavior
  there is the main unknown; the design fails closed, so an LTSC failure would surface
  as preflight `sandbox_unavailable` evidence, not silent degradation. P0 completes
  only after the security owner reviews evidence on all target Windows builds.
