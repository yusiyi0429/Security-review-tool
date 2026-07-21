# Pilot Runbook

This document provides a **complete synthetic workflow** for a non-developer
pilot user. Follow every step, in order, using only the documentation
referenced. If you encounter confusion, ambiguity, or an error, record the
issue with:
- The step number.
- What you expected.
- What actually happened (screenshot if helpful).
- Which document you were consulting.

## Prerequisites

- [ ] You have received the release ZIP and SHA-256 sidecar from the pilot
  coordinator (internal file share, secure transfer, or release portal).
- [ ] You have a Windows machine matching the [Quick Start](quick-start.md)
  prerequisites.
- [ ] You have access to an intranet LLM endpoint (credentials provided by
  your team lead or pilot coordinator).
- [ ] You have one or more test assets (files, directories, archives) that
  you would normally want to review for sensitive content. At minimum,
  prepare:
  - A ZIP archive containing a mix of text and OpenXML files.
  - A standalone PDF file.
  - A directory with mixed file types (include at least one `.exe` or `.dll`
    to observe unsupported-format gaps).

## Phase 1: Install and Verify

### Step 1: Verify the package

Follow [Quick Start, Section 1](quick-start.md#1-download-and-verify):

```powershell
Get-FileHash -Algorithm SHA256 SecurityReviewTool-1.0.0-win-x64.zip
```

- [ ] Hash matches the published value in the `.sha256` sidecar.

### Step 2: Extract to a long/spaced/Chinese path

Create a directory with a path that contains spaces and non-ASCII characters,
such as:

```
D:\内部安全审查\工具 v1.0\SecurityReviewTool\
```

Extract the ZIP there:

```powershell
Expand-Archive -LiteralPath SecurityReviewTool-1.0.0-win-x64.zip `
  -DestinationPath "D:\内部安全审查\工具 v1.0\SecurityReviewTool\"
```

- [ ] Extraction succeeds without errors.

### Step 3: Start the tool

Double-click `SecurityReviewTool.exe` from the extracted directory.

- [ ] Main window appears within 5 seconds.
- [ ] No UAC or administrator prompt appears.
- [ ] No Windows SmartScreen warning (if one appears, note it; see
  [Diagnostics](diagnostics-and-support.md)).

## Phase 2: First Scan (No LLM)

### Step 4: Scan a simple directory

1. Click **New Scan**.
2. Browse to your mixed-file directory.
3. Observe the **Coverage Status** — note which files are Covered, Partial,
   or Unsupported.

- [ ] Coverage status is shown before the scan starts.
- [ ] The status matches your expectations (e.g., `.exe` files are
  Unsupported, `.docx` files are Covered).

### Step 5: Run the scan

Click **Scan**.

- [ ] Progress bar appears and advances.
- [ ] No error dialog appears.
- [ ] Scan completes (or shows gaps if unsupported files are present).

### Step 6: Review findings

1. Browse the findings grid.
2. Click a finding to see the excerpt and location.
3. **Confirm** at least two findings.
4. **Dismiss** at least one finding (you must provide a reason).
5. **Mark as Exception** one finding (provide owner and expiry).

- [ ] Review actions are saved (close and reopen the scan to confirm).
- [ ] The Coverage tab lists every gap.

### Step 7: Export XLSX

Click **Export XLSX** and save to your Desktop.

- [ ] File is created.
- [ ] Open the XLSX and verify all six sheets are present (see
  [XLSX Report Guide](xlsx-report.md#six-sheet-structure)).
- [ ] Check that the **Gaps** sheet lists the unsupported `.exe` files.
- [ ] Check that the **Review** sheet shows your confirmed/dismissed/exception
  decisions.

> ⚠ **Note:** The XLSX contains full match text. Handle the file according
> to your organization's data policy.

### Step 8: Rescan

1. Go back to the scan in the tool.
2. Click **Rescan**.
3. Verify the scan re-runs and produces a new set of findings.

- [ ] Rescan completes without errors.

### Step 9: Cancel a scan

1. Start a new scan on a large directory.
2. Click **Cancel** while the scan is running.

- [ ] Scan stops.
- [ ] Partial results are preserved.
- [ ] Gaps are recorded for unprocessed files.

## Phase 3: LLM-Enabled Scan

### Step 10: Configure LLM

Follow the [LLM Configuration Guide](llm-configuration.md):

1. Go to **Settings → LLM**.
2. Enter your intranet LLM endpoint URL (must start with `https://`).
3. Enter your API key.
4. Enter the model name provided by your team lead.
5. Click **Test Connection**.

- [ ] Connection test succeeds.
- [ ] If test fails, record the error and consult the
  [troubleshooting table](llm-configuration.md#troubleshooting).

### Step 11: Scan with LLM

Run a scan on a directory that contains text files with known sensitive
content (your team lead should provide a test set, or use a sample PDF).

- [ ] Scan completes.
- [ ] Findings include both deterministic and LLM-semantic results (the LLM
  results indicate the LLM model used).

### Step 12: Review LLM findings

- [ ] LLM-reviewed findings show the model name and prompt version.
- [ ] An LLM finding can be confirmed, dismissed, or marked as exception
  (same workflow as Phase 2).

### Step 13: Simulate LLM unavailability

1. Temporarily change the LLM endpoint to an invalid URL (e.g.,
   `https://invalid.example.com/v1/chat/completions`).
2. Run a scan.

- [ ] Scan completes with gaps classified as `LlmUnavailable`.
- [ ] The Coverage tab and the XLSX Gaps sheet list these gaps.
- [ ] The tool does not crash or freeze.

3. Restore the correct LLM endpoint after this step.

## Phase 4: Rule Pack (if available)

### Step 14: Import a rule pack

If the pilot coordinator provides a signed rule pack:

1. Go to **Settings → Rules**.
2. Click **Import Rule Pack**.
3. Select the signed `.zip`.

- [ ] Import succeeds (see [Rule Import](rule-import.md) guide).
- [ ] Preflight check passes.

### Step 15: Scan with updated rules

Rescan the same asset from Phase 2.

- [ ] If the rule pack changed detection behavior, the findings change
  accordingly.
- [ ] The scan metadata shows the new rule pack version.

## Phase 5: Diagnostics and Cleanup

### Step 16: Collect diagnostics

Follow [Diagnostics and Support](diagnostics-and-support.md#collecting-diagnostics-for-support):

1. Go to **Settings → Diagnostics**.
2. Click **Collect Diagnostics**.

- [ ] ZIP file is created in your Documents folder.
- [ ] Open the ZIP and verify it contains `app.log`, `health.json`, and
  `app-settings.json` (with credentials redacted).

### Step 17: Clear data

If you are done testing or want to start fresh, follow the
[Uninstall Guide](uninstall-and-clear-data.md#partial-uninstall-clear-data-keep-application):

1. Close the tool.
2. Delete `%LOCALAPPDATA%\SecurityReviewTool\`.
3. Restart the tool.

- [ ] Tool starts with fresh defaults (no previous scan history).
- [ ] LLM configuration is cleared — you must re-enter it.

## Phase 6: Complete Uninstall

Follow [Uninstall and Clear Data](uninstall-and-clear-data.md):

1. Export any XLSX reports you want to keep.
2. Delete the application directory.
3. Clear `%LOCALAPPDATA%\SecurityReviewTool\`.
4. Note that the AppContainer profile persists but is harmless.

- [ ] No files remain in the install location.
- [ ] `Test-Path "$env:LOCALAPPDATA\SecurityReviewTool"` returns `False`.

## Issue Log

Copy and fill this template for each issue you encounter:

```
Step: ___
Document consulted: ___
Expected: ___
Actual: ___
Severity (cosmetic / confusing / blocking): ___
```

Return the completed issue log and all exported XLSX files to the pilot
coordinator.
