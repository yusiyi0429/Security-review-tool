# XLSX Report Guide

SecurityReviewTool exports scan results as a six-sheet XLSX workbook. This
document explains each sheet's content, the cell value limits, control
character handling, and the atomic failure model.

## Six-Sheet Structure

### Sheet 1: Summary

| Column | Content |
|--------|---------|
| Scan ID | Unique identifier for this scan run. |
| Asset Path | The scanned file, directory, or archive path. |
| Start / End | Scan timestamps in ISO 8601 UTC. |
| Total Files | Count of inventoried files. |
| Parser Assignments | Files per parser. |
| Findings | Total detections by severity. |
| Reviewed | Count of confirmed / dismissed / exception. |
| Gaps | Total coverage gaps. |
| Rule Pack | Active rule pack version and signer key ID. |
| LLM Model | Configured model name and prompt version. |
| Tool Version | SecurityReviewTool version and runtime. |

### Sheet 2: Findings

Every detection, one row per finding:

| Column | Content |
|--------|---------|
| Finding ID | Sequential identifier. |
| Severity | Critical / High / Medium / Low / Info. |
| Detector ID | Rule or detector that produced the match. |
| File | Relative path within the asset. |
| Location | Parser-specific locator (page, part, offset). |
| Excerpt | The matched text with surrounding context. |
| Match Start/End | Character offset of the exact match within the excerpt. |
| Review Status | Pending / Confirmed / Dismissed / Exception. |
| Reviewer Notes | Free-text review comment. |

### Sheet 3: Review

Per-finding review decisions:

| Column | Content |
|--------|---------|
| Finding ID | Link to Findings sheet. |
| Decision | Confirmed / Dismissed / Exception. |
| Reviewer | Windows user identity at time of decision. |
| Timestamp | UTC decision time. |
| Reason | Required free-text (for Dismissed and Exception). |
| Exception Owner | For Exception: accountable person. |
| Exception Expiry | For Exception: review-by date. |

### Sheet 4: Gaps

Every coverage gap, one row:

| Column | Content |
|--------|---------|
| Gap ID | Sequential identifier. |
| File | Relative path. |
| Classification | Stable gap code (see Coverage document). |
| Detail | Human-readable description. |
| Parser | Assigned or attempted parser. |
| Timestamp | When the gap was recorded. |

### Sheet 5: Assets

Full file inventory:

| Column | Content |
|--------|---------|
| Path | Relative path within the asset. |
| Size | File size in bytes. |
| SHA-256 | File hash. |
| Parser | Assigned parser (or "none"). |
| Classification | Text / Binary / Archive-entry / Model. |
| Status | Covered / Partial / Unsupported / Failed. |

### Sheet 6: Configuration

Scan parameters for reproducibility:

| Column | Content |
|--------|---------|
| Parameter | Configuration key. |
| Value | Configuration value. |

Includes: rule pack version, rule pack SHA-256, signer key ID, detector
identities, LLM endpoint (hostname only), LLM model, prompt version,
prompt SHA-256, concurrency settings, scan root, pattern filters.

## Full-Value Warning

> ⚠ **The XLSX contains the full text of every detected match and its**
> **surrounding context.** This includes potential secrets, credentials,
> API keys, internal hostnames, source-code snippets, and other sensitive
> content. Treat the exported XLSX as a **controlled document** with access
> restricted to authorized reviewers and security personnel.

The tool does not redact, mask, or summarize excerpts in the XLSX output.
The XLSX is the **evidence record** of the review — it must faithfully
represent what was detected and reviewed.

## Control Character Representation

XLSX cells cannot contain certain control characters (U+0000–U+001F except
U+0009 TAB, U+000A LF, U+000D CR). When an excerpt contains prohibited
control characters, the tool replaces them with reversible escape sequences:

| Character | Escape Sequence |
|-----------|----------------|
| U+0000 (NUL) | `\x00` |
| U+0001–U+0008 (SOH–BS) | `\x01`–`\x08` |
| U+000B (VT) | `\x0B` |
| U+000C (FF) | `\x0C` |
| U+000E–U+001F (SO–US) | `\x0E`–`\x1F` |

The escape sequences are **reversible** — `\x` followed by two hex digits
always decodes to the corresponding byte. This means:

- The XLSX excerpt is not lossy with respect to the original content.
- If a legitimate backslash-lowercase-x sequence appears in the original
  content, it is NOT double-escaped — the original and escaped forms are
  distinguishable because the escape only fires for bytes that are
  prohibited in XLSX cells.
- The Findings sheet header notes whether any control-character escaping was
  applied.

## Cell Limits

| Limit | Value |
|-------|-------|
| Max characters per cell | 32,767 |
| Max data rows per sheet | 1,048,575 (Excel row limit minus header row) |
| Max hyperlinks per sheet | 65,530 (OpenXML limit) |

**Handling of limit violations:**

- **Cell exceeds 32,767 characters:** The content is truncated at 32,767
  characters and the cell suffix ` [TRUNCATED]` is appended. The original
  full text is stored in the encrypted local database and can be reviewed
  in the application UI.
- **Sheet exceeds 1,048,575 data rows:** The sheet is split into multiple
  sheets named `<SheetName>_1`, `<SheetName>_2`, etc.
- **Fatal OpenXML limits:** If row splitting would exceed the maximum number
  of sheets, or if a structural limit (column count, style count) is hit,
  the export fails atomically (see below).

## Atomic Failure Behavior

The XLSX export is **atomic**:

1. The workbook is built in a temporary file in the temp directory.
2. If any error occurs during construction — including cell limit violations
   that cannot be resolved by splitting, OpenXML structural limits, or I/O
   errors — the temporary file is deleted.
3. No partial, corrupted, or truncated XLSX file appears at the output path.
4. The error is reported to the user with:
   - The sheet and row where the error occurred.
   - The specific limit that was hit.
   - A suggestion (e.g., "reduce scan scope" or "split into multiple scans").

The user can retry the export after adjusting the scan (e.g., filtering by
severity, excluding unsupported files, or splitting large directories into
multiple scans).

## XLSX Integrity

Each exported XLSX contains:

- `custom.xml` with a scan ID, tool version, and export timestamp.
- The scan ID matches the database record and the Summary sheet.

The SHA-256 of the exported XLSX is logged in the diagnostics log for
chain-of-custody purposes.

## Post-Export

After export:

1. The XLSX is saved to your chosen location.
2. Its SHA-256 is recorded in the diagnostics log.
3. The Export History in **Settings → History** records the path, timestamp,
   and hash.
4. **The XLSX is your responsibility.** The tool does not manage, encrypt,
   or track the exported file after it is written. Apply your organization's
   data-handling policies to the file.
