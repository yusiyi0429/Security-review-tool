# Coverage and Conclusions

This document enumerates every supported, partially-supported, and unsupported
format in SecurityReviewTool v1.0.0, and defines the exact bounded conclusions
the tool can draw from a scan.

## Design Rule: No Scan Is "Complete"

A scan result **never shows a green "complete" status** if any coverage gap
exists. Every gap is recorded individually and surfaced in:

- The **Coverage** tab of the review grid.
- The **Gaps** sheet of the exported XLSX.
- The scan summary statistics.

The reviewer is responsible for assessing whether residual gaps are acceptable
for the release or asset under review.

## Covered Formats

These formats have a dedicated parser that extracts structured content for
detector application. All applicable detectors run on extracted content.

| Format | Parser ID | Content Extracted | Entry Limits |
|--------|-----------|-------------------|--------------|
| **ZIP** (including JAR, APK, EPUB) | `zip` | Entry tree with paths, sizes; child asset discovery | 100K entries, depth 5, 4 GiB/entry, 50 GiB total |
| **TAR** (GNU, POSIX, ustar) | `tar` | Entry tree with paths, sizes, symlink/hardlink detection; child discovery | 100K entries, depth 5, 4 GiB/entry, 50 GiB total |
| **GZip** | `gzip` | Single-file decompression and child discovery | Uncompressed ≤ declared × 10, 4 GiB/entry |
| **Text** (UTF-8, UTF-16, GB18030) | `text` | Full text content in 512 KiB chunks, 1 MiB frames | 8,192 location-map entries |
| **PDF** (via PdfPig 0.1.14) | `pdf` | Page text, metadata, annotations, form fields, bookmarks, attachments | 10 MiB text/page, 1M characters/page, ≤64 MiB attachments |
| **OpenXML** (DOCX, XLSX, PPTX) | `openxml` | Paragraphs, tables, headers/footers (DOCX); cells (XLSX); slides/notes (PPTX); metadata; VBA | OLE CFB detection, 512 KiB chunks |
| **SafeTensors** | `model` | Header JSON → metadata (tensor names, shapes, dtypes) | Pickle detection (dangerous rejection) |
| **GGUF v2/v3** | `model` | KV metadata pairs, tensor shapes | Excessive KV count detection |
| **ONNX** | `model` | ir_version, graph, opset → metadata | Protobuf walk, shape inference |

### Text Classification

The text parser classifies each file as text or binary using heuristic
byte-distribution analysis. Files classified as binary are treated as
`UnsupportedFormat` when no other parser applies. This classification is
recorded per-file and cannot be manually overridden.

## Partially Supported Formats

These formats have a dedicated parser but with known limitations that create
coverage gaps for some content.

| Format | Parser | Supported | Not Supported |
|--------|--------|-----------|---------------|
| **GZip** | `gzip` | Single-member gzip; child discovery | Multi-member gzip (only first member); bzip2, xz, zstd |
| **Model** | `model` | SafeTensors metadata, GGUF KV+shapes, ONNX graph metadata | SafeTensors with external data files; ONNX external data; full tensor content scanning |
| **OpenXML** | `openxml` | DOCX paragraphs/tables/headers; XLSX cells; PPTX slides/notes | Legacy .doc/.xls/.ppt; encrypted documents; embedded OLE objects beyond VBA |
| **PDF** | `pdf` | Page text, annotations, forms, bookmarks | Encrypted PDF (detected and reported as gap); XFA forms; 3D content |
| **TAR** | `tar` | Regular files, directories, symlinks, hardlinks | GNU sparse files (treated as regular); pax extended headers beyond basic path/size |

## Unsupported Formats

These formats have no dedicated parser. Files in these formats produce
`UnsupportedFormat` coverage gaps.

| Format | File Types | Gap Classification |
|--------|------------|--------------------|
| **PE (Windows executables)** | `.exe`, `.dll`, `.sys` | `UnsupportedFormat` |
| **ELF (Linux executables)** | (no extension convention) | `UnsupportedFormat` |
| **Java Class** | `.class` | `UnsupportedFormat` |
| **Raw Binary** | Files classified as binary by the text heuristic | `UnsupportedFormat` |
| **Empty** | Zero-length files | `UnsupportedFormat` |

## Explicitly Excluded from v1.0.0

The following are not supported and are not planned for v1.x:

- **Legacy Office formats** (`.doc`, `.xls`, `.ppt`) — no parser.
- **Encrypted files** — detected and reported as gap; no decryption.
- **Dynamic analysis** — no file execution or sandbox evaluation.
- **Full decompilation/disassembly** — no IL or machine-code analysis.
- **OCR** — no image-based text extraction.
- **Model weight leakage analysis** — metadata only; no tensor-scanning for secrets.
- **Docker engine connection** — only static TAR/OCI layout analysis.
- **Git history** — only current file tree.
- **Network service** — standalone desktop application only.
- **Reports beyond XLSX** — PDF, HTML, JSON reports not in v1.

## Failure Classifications

Every gap and failure is classified with a stable code:

| Code | Condition |
|------|-----------|
| `UnsupportedFormat` | No parser registered for the detected or declared format. |
| `ParseFailed` | Parser threw an exception or returned an internal error. |
| `Encrypted` | File is encrypted or password-protected (detected by parser). |
| `Truncated` | File content is shorter than the declared size. |
| `EntryLimitExceeded` | Archive entries exceed the parser's maximum. |
| `DepthExceeded` | Archive nesting exceeds the parser's maximum depth. |
| `SizePerEntryExceeded` | A single archive entry exceeds the 4 GiB limit. |
| `TotalSizeExceeded` | Total archive size exceeds the 50 GiB limit. |
| `BinaryByHeuristic` | Text parser classified the file as binary and no other parser applies. |
| `ParserMemory` | Worker exceeded the per-file memory limit (384 MiB ordinary / 1 GiB OCI). |
| `ParserTimeout` | Worker exceeded the per-file time limit. |
| `ParserCrash` | Worker process terminated with a non-zero exit code. |
| `ParserProtocolMismatch` | Worker handshake or protocol error. |
| `LlmUnavailable` | LLM endpoint unreachable during semantic review of a region. |
| `DetectorError` | A detector threw an exception during rule evaluation. |

## Bounded Conclusions

SecurityReviewTool can conclude **only** the following from a scan:

1. **The tool ran the registered parsers and detectors on the input asset
   under the configured rules and LLM**, producing the reported findings.
2. **Every detected match** was presented in the review grid with its
   location, detector ID, severity, and excerpt.
3. **Every coverage gap** was recorded and is listed in the Coverage tab
   and the exported XLSX Gaps sheet.
4. **No unsupported format was silently skipped** — each is a documented gap.
5. **The review disposition** (confirmed / dismissed / exception) represents
   the reviewer's judgment, not the tool's.

The tool **cannot** conclude:

- That an asset is "safe" or "free of sensitive data".
- That all sensitive content has been found (semantic review is probabilistic).
- That format-specific limits (entry count, depth, size) are sufficient for
  every asset — exceeding a limit produces a documented gap, not a false
  negative.
- That a dismissed finding is definitively a non-issue (only the reviewer
  determines this).
- That LLM coverage is complete (LLM unavailability creates documented gaps).
