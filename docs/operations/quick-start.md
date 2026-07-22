# Quick Start

This guide walks a non-developer pilot user through downloading, verifying,
and running SecurityReviewTool for the first time.

## Prerequisites

- **Windows 11 x64 (supported builds only)**.
- No .NET runtime, Docker, Java, Python, or Office installation required.
- The tool runs as the current user — **no administrator rights needed**.
- An intranet LLM endpoint (OpenAI-compatible) if you plan to use semantic review.

## 1. Download and Verify

Obtain the installer and its SHA-256 sidecar from an approved distribution
channel (internal file share, release portal, or secure transfer):

```
SecurityReviewTool-1.0.3-win-x64-setup.exe
SecurityReviewTool-1.0.3-win-x64-setup.exe.sha256
```

Verify the installer hash before running it:

```powershell
Get-FileHash -Algorithm SHA256 SecurityReviewTool-1.0.3-win-x64-setup.exe
```

Compare the output against the published hash in the `.sha256` sidecar or the
release announcement. **Do not use the tool if the hashes do not match.**

If the release is Authenticode-signed, also check the signature:

```powershell
Get-AuthenticodeSignature SecurityReviewTool-1.0.3-win-x64-setup.exe
```

The `Status` must be `Valid`. An unsigned pilot build carries a prominent
**UNSIGNED PILOT** warning and should only be used in authorized test
environments.

## 2. Install

Double-click the installer. It installs for the current user under:

```
%LOCALAPPDATA%\Programs\SecurityReviewTool\
```

No administrator rights are requested. A Start Menu shortcut is created, and
you may optionally create a desktop shortcut. Keep **Launch SecurityReviewTool**
selected on the final page to open the application immediately.

The installer upgrades an existing installation in place. Uninstalling the
application does not automatically delete scan history or settings under
`%LOCALAPPDATA%\SecurityReviewTool`; see
[Uninstall and Clear Data](uninstall-and-clear-data.md).

### Portable ZIP (optional)

Extract the ZIP to **any user-writable directory** (Desktop, Documents, or a
dedicated tools folder all work):

```powershell
Expand-Archive -LiteralPath SecurityReviewTool-1.0.3-win-x64.zip -DestinationPath C:\Tools\SecurityReviewTool
```

**Long, spaced, and Chinese-character paths are supported.** For example,
`D:\内部安全审查\工具 v1\SecurityReviewTool\` works correctly.

The extracted directory contains:

```
SecurityReviewTool.exe          ← double-click to start
Assets/rules/                   ← rule configuration files
worker/                         ← isolated parser sandbox (do not modify)
release-manifest.json           ← integrity manifest
README*.md                      ← release notes
```

## 3. Start the Tool

Open **安全审查工具** from the Start Menu. Portable users can double-click
`SecurityReviewTool.exe` in the extracted directory. No service or scheduled
task is created.

The main window should appear **within 5 seconds** of launch. If it does not,
see [Diagnostics and Support](diagnostics-and-support.md).

On first launch, the tool creates writable data under:

```
%LOCALAPPDATA%\SecurityReviewTool\
```

This is normal. No files are created outside `%LOCALAPPDATA%` (except the
AppContainer profile, which is a system-managed isolation object — see
[Uninstall](uninstall-and-clear-data.md)).

## 4. Select an Asset to Scan

1. Click **New Scan** or drag a file/directory onto the window.
2. Navigate to the asset you want to review.
3. The tool accepts **individual files, directories, Docker TAR archives,
   and OCI Image Layout directories**.

Supported formats are listed in the [Coverage](coverage-and-conclusions.md)
document. Each scanned asset type shows a coverage status before the scan
starts:

| Status | Meaning |
|--------|---------|
| **Covered** | A dedicated parser and all applicable detectors are available. |
| **Partial** | The format can be parsed, but some detector categories are unavailable. |
| **Unsupported** | No parser exists for this format; the file is treated as binary. |
| **Gap** | A coverage gap is recorded — see Coverage document for details. |

## 5. Run the Scan

Click **Scan**. The tool:

1. Walks the asset tree and builds a file inventory.
2. Dispatches files to the isolated parser sandbox (no network access).
3. Runs deterministic detectors (regex, keyword, entity, structure).
4. If LLM is configured, dispatches detected regions for semantic review.
5. Compiles results into the review grid.

A progress bar shows scan status. You can **cancel** at any time — partial
results are preserved and documented as coverage gaps.

## 6. Review Results

The review grid shows:

- **Severity** — Critical, High, Medium, Low, or Info.
- **Detector** — the rule or detector that flagged the region.
- **Location** — file path, page/part, and character offset.
- **Excerpt** — the matched content with surrounding context.

For each finding, you can:

- **Confirm** — accept the finding as valid.
- **Dismiss** — mark as non-issue with a required free-text reason.
- **Exception** — record as known and accepted with owner and expiry.
- **Rescan** — re-scan the asset after changing rules or LLM configuration.

All review decisions are saved immediately to the encrypted local database.

## 7. Export XLSX Report

Click **Export XLSX** to produce the six-sheet evidence workbook:

| Sheet | Content |
|-------|---------|
| Summary | Scan metadata, coverage summary, statistics. |
| Findings | All detections with location, severity, and review disposition. |
| Review | Per-finding review decisions with reviewer notes. |
| Gaps | Every coverage gap (unsupported format, parse failure, LLM unavailable, etc.). |
| Assets | Full asset inventory with parser assignment. |
| Configuration | Rule pack version, LLM model, prompt version, scan parameters. |

> ⚠ **Important:** The XLSX contains the **full text** of sensitive matches
> and their surrounding context. Treat the XLSX as a controlled document.
> See the [XLSX Report Guide](xlsx-report.md) for cell limits, control
> character handling, and atomic failure behavior.

## 8. What Makes a Scan "Complete"

A scan is **never shown as "complete"** if any coverage gap exists. Gaps include:

- Files in unsupported formats (e.g. PE binaries, ELF binaries).
- Files that could not be parsed (encrypted, corrupt, truncated).
- Format-specific limits exceeded (entry count, depth, size per entry).
- LLM unavailable for semantic review of text regions.
- Detector errors.
- Cancelled or timed-out worker tasks.

The **Coverage** tab and the exported XLSX enumerate every gap. The reviewer
must assess whether the residual gaps are acceptable for the release being
reviewed.

## Next Steps

- [Configure LLM](llm-configuration.md) for semantic review.
- [Import rules](rule-import.md) to update detection coverage.
- [Understand the XLSX report](xlsx-report.md).
- [Read the full coverage document](coverage-and-conclusions.md).
- [Diagnose issues](diagnostics-and-support.md).
