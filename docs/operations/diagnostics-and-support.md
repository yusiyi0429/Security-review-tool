# Diagnostics and Support

This document explains how to collect diagnostic information, interpret logs,
and troubleshoot common issues with SecurityReviewTool.

## Diagnostic File Locations

All diagnostic files are under `%LOCALAPPDATA%\SecurityReviewTool\`:

```
%LOCALAPPDATA%\SecurityReviewTool\
├── config\              # Non-secret configuration and DPAPI-protected secrets
│   ├── app-settings.json
│   └── llm-credential   (DPAPI-encrypted)
├── data\
│   └── history.db       # Encrypted SQLite (AES-256-GCM)
├── rules\               # Active and historical rule packs
│   ├── baseline\        # Shipped baseline (immutable)
│   └── imported\        # User-imported rule packs
├── temp\                # Task-level temporary data
│   └── <scan-id>\       # Cleared on scan completion or tool exit
└── diagnostics\         # Sanitized runtime logs
    ├── app.log          # Main process log (current session)
    ├── app.1.log        # Previous session (rotated)
    ├── worker.log       # Worker sandbox log (sanitized)
    └── health.json      # Last startup health check result
```

## Log Sanitization

Diagnostic logs are **sanitized before writing**:

- Absolute file paths outside the scan root are replaced with
  `<external-path>`.
- IP addresses are replaced with `<ipv4>` or `<ipv6>`.
- Hostnames in LLM endpoint URLs are replaced with `<llm-host>`.
- Pipe names are replaced with `<pipe>`.
- AppContainer SIDs are replaced with `<appcontainer-sid>`.
- User SIDs and usernames are replaced with `<current-user>`.

The following are **never logged**:

- LLM API keys or credentials.
- File contents or excerpts from scanned assets.
- Database encryption keys (protected by DPAPI, never materialized as
  plaintext in the log).
- Network packet payloads.

## Startup Health Check

Every launch runs a preflight health check. The result is written to
`diagnostics/health.json`:

```json
{
  "timestamp": "2026-07-21T12:00:00Z",
  "checks": {
    "app_data_writable": true,
    "database_healthy": true,
    "sandbox_available": true,
    "baseline_rules_valid": true,
    "trusted_signers_valid": true
  },
  "overall": "pass"
}
```

If `overall` is `fail`, the failing check blocks startup with a specific
error message. There is no "continue anyway" path.

### Health Check Failure Codes

| Code | Meaning | Resolution |
|------|---------|------------|
| `root_invalid` | The tool executable path or app data root is invalid. | Re-extract the ZIP to a writable directory. |
| `baseline_inactive` | The baseline rule pack is missing or corrupted. | Re-extract the original ZIP; do not modify `Assets/rules/`. |
| `app_data_not_writable` | Cannot write to `%LOCALAPPDATA%\SecurityReviewTool\`. | Check disk space and permissions. |
| `database_unhealthy` | The history database cannot be opened or decrypted. | Delete `data/history.db` (this clears history). |
| `sandbox_unavailable` | Worker sandbox cannot be created on this OS. | Verify the OS is Windows 11 x64 (supported builds only). |
| `trusted_signers_invalid` | `trusted-signers.json` is missing or malformed. | Re-extract the original ZIP. |

## Collecting Diagnostics for Support

To share diagnostic information with the operations or security team:

1. Open **Settings → Diagnostics**.
2. Click **Collect Diagnostics**.
3. The tool gathers:
   - `app.log` and `app.1.log` (sanitized).
   - `health.json`.
   - `app-settings.json` (credentials redacted).
   - `release-manifest.json` (from the install directory).
   - OS version and build number (not serial or machine ID).
4. The gathered files are packaged as a timestamped ZIP in your Documents
   folder: `SecurityReviewTool-diagnostics-YYYYMMDD-HHMMSS.zip`.
5. **Review the ZIP contents before sharing** — confirm that no sensitive
   information is present (paths, hostnames beyond what's already sanitized).
6. Share through your organization's approved channel.

The diagnostics ZIP **never** includes:

- Database files (`history.db`).
- LLM credentials.
- Scan content or excerpts.
- Rule pack private keys (the client never possesses these).

## Allowlist of Supported Scenarios

The following are supported operational scenarios. Issues outside this
allowlist should be escalated to the development team.

| Scenario | Self-Service | Escalation |
|----------|-------------|------------|
| Tool won't start | Check health codes above; re-extract ZIP | If `sandbox_unavailable`, verify OS version |
| Scan hangs | Cancel scan; restart tool; if repeatable, collect diagnostics | Share diagnostics ZIP |
| LLM connection fails | Verify endpoint URL, key, and network; use Test Connection | If test passes but scan fails, collect diagnostics |
| Rule import fails | Check signature and version; see Rule Import guide | If pack is valid but rejected, share pack metadata (not content) |
| XLSX export fails | Reduce scope; check disk space | Share error details from the failure dialog |
| Worker crashes | Restart; if repeatable, collect diagnostics | Include the asset type and crash error code |
| Slow scan | Check asset size; large archives take time | Share performance counters if available |
| Cannot clear data | Run uninstall procedure from Uninstall guide | Escalate if AppContainer profile cannot be removed |

## Common Issues

### "Parser sandbox unavailable"

The tool requires Windows 11 x64 (supported builds only). Other Windows
editions are not in the .NET 10 support matrix and may not support
AppContainer with the required isolation properties. If the preflight check
fails, the OS is not supported for this release.

### Windows Defender or SmartScreen warning

The portable EXE may trigger a SmartScreen warning on first launch because
it is not commonly downloaded. This is expected for a new internal tool.
The warning can be dismissed after the hash is verified. Do not disable
Defender or SmartScreen — the tool is designed to operate with both enabled.

### "File not found" during scan

If a file is deleted or moved during scanning, the tool reports a gap with
classification `ParseFailed` and description "file removed during scan."
Re-run the scan on a stable copy of the asset.

### Disk space exhausted

Large archival assets (TAR, ZIP) are decompressed in the temp directory.
Ensure `%LOCALAPPDATA%\SecurityReviewTool\temp\` has sufficient free space
(roughly 2× the archive size for extraction overhead). The temp directory
is cleaned on scan completion or tool exit.
