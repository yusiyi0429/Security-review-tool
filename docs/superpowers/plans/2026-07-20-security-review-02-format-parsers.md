# Security Review P2 Format Parser Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded static parsing for structured files, Open XML, PDF, Python/JAR/JVM/binaries, Docker/OCI, and safe model metadata, with reproducible locations or explicit coverage gaps for every region.

**Architecture:** Every adapter implements the P1 `IFormatParser` contract and runs only inside the AppContainer worker. Adapters emit normalized chunks, virtual children, and typed gaps; they never produce risk decisions. Third-party libraries remain behind narrow adapters and are tested against a versioned synthetic/adversarial corpus.

**Tech Stack:** `System.Text.Json`, `XmlReader`, custom streaming CSV/JVM/PE/ELF/OCI/model readers, YamlDotNet 18.1.0 event API, Open XML SDK 3.5.1, PdfPig 0.1.14, ZIP/TAR core from P1.

## Global Constraints

- Never deserialize arbitrary YAML tags, .NET/Python objects, pickle, Java objects, Office macros, or model weights.
- Never load external XML entities, Office relationships, PDF links, Docker registry/daemon, or container entrypoints.
- Each adapter is streaming or explicitly bounded; a parser crash/timeout/OOM becomes a gap and never crashes the coordinator.
- Every location is reproducible from the original file: line/column, JSON/YAML/XML path, Sheet/cell, page/block, nested path, constant-pool index, byte offset, or OCI layer digest/path.
- Third-party parser upgrades are isolated commits and must pass the complete adapter corpus.
- Unsupported regions are part of the expected test result, not skipped tests.

---

## Task P2-T1: Implement JSON, XML, CSV, and YAML adapters

**Files:**
- Create: `src/SecurityReview.Parsers/Structured/JsonFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Structured/JsonPathTracker.cs`
- Create: `src/SecurityReview.Parsers/Structured/OversizeJsonTokenSkipper.cs`
- Create: `src/SecurityReview.Parsers/Structured/XmlFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Structured/CsvFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Structured/CsvDialectDetector.cs`
- Create: `src/SecurityReview.Parsers/Structured/YamlFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Structured/YamlEventGuard.cs`
- Create: `tests/SecurityReview.UnitTests/Parsers/StructuredPathTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Structured/StructuredParserTests.cs`
- Create: `tests/Corpus/Structured/generate-structured-corpus.ps1`

**Interfaces:**
- Consumes: `IFormatParser`, `ContentChunker`, `SourceLocator`, `ArchiveBudget`.
- Produces: chunks with JSON Pointer, XPath-like, CSV row/column/header, and YAML path/line/column locators.

- [ ] **Step 1: Write exact path/location tests before adapters**

Generate runtime fixtures where a canary appears at JSON `/users/1/token`, XML `/root/user[2]/token[1]/text()`, CSV row 3 column 2 header `token`, and YAML `users[1].token`. Assert logical value, original byte range or line/column, structure key and value chunks, and deterministic ordering.

Add malformed trailing data, duplicate JSON keys, XML DTD/entity, CSV unclosed quote/ambiguous delimiter, YAML recursive alias/tag/depth/event-count samples. Each sample must return valid earlier chunks plus the expected `Corrupt`, `UnsupportedRegion`, or `ArchiveLimit` gap.

- [ ] **Step 2: Run the structured corpus filter and observe missing adapters**

```powershell
pwsh tests/Corpus/Structured/generate-structured-corpus.ps1
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~StructuredParserTests
```

Expected: FAIL because structured parser classes are missing.

- [ ] **Step 3: Implement streaming JSON tokens and pointer tracking**

Use `Utf8JsonReader` with `CommentHandling=Disallow`, `AllowTrailingCommas=false`, `MaxDepth=128`, and `isFinalBlock` state across 128 KiB buffers. `JsonPathTracker` maintains object property names and array indices and emits RFC 6901 escaping (`~`→`~0`, `/`→`~1`). Emit property names and primitive values separately with byte offsets. Reject duplicate property names within the same object as `json_duplicate_property` while retaining both locations for scanning.

Do not construct `JsonDocument` for arbitrary input. Retain at most 1 MiB for one incomplete token. If a JSON string token exceeds that bound, `OversizeJsonTokenSkipper` scans bytes with explicit quote/backslash/Unicode-escape state to the closing delimiter, emits the already validated bounded prefix for detection, records `json_string_over_limit` for the skipped range, and resumes only if the following structural delimiter is valid. Never claim the oversized value fully covered and never grow a buffer to the token's declared/observed length.

- [ ] **Step 4: Implement XML with external access disabled**

Create `XmlReaderSettings` exactly as follows:

```csharp
var settings = new XmlReaderSettings
{
    Async = true,
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersInDocument = context.Limits.MaxExpandedBytesRemaining,
    MaxCharactersFromEntities = 0,
    IgnoreComments = false,
    IgnoreProcessingInstructions = false,
    IgnoreWhitespace = false
};
```

Track sibling element indices, attributes, text, comments, and processing-instruction data. Never resolve schema locations or XInclude. DTD presence produces `UnsupportedRegion` code `xml_dtd_prohibited`; malformed tail produces `Corrupt` after earlier safe chunks.

- [ ] **Step 5: Implement explicit CSV state machine**

`CsvDialectDetector` samples at most 64 KiB and scores comma, tab, semicolon, and pipe by stable field count across the first 20 logical rows; ties or inconsistency produce `csv_dialect_ambiguous`. `CsvFormatParser` supports RFC 4180 double-quote escaping and CRLF/LF, max 10,000 columns, max 1 MiB field, and preserves row/column/optional first-row header. It does not invoke spreadsheet formula semantics.

- [ ] **Step 6: Implement YAML from low-level events only**

Instantiate YamlDotNet `Parser`, never `Deserializer`, `Serializer`, type resolver, or tag mapping. Because the library materializes scalar event values, use structured YAML parsing only when the brokered stream is ≤64 MiB; larger YAML uses strict text scanning plus `yaml_structure_size_limit`. `YamlEventGuard` counts maximum depth 128, 1,000,000 events, 10,000 aliases, per-scalar length 1 MiB, and a per-anchor expansion factor of 100. Emit scalar keys/values with `Mark.Line/Column`, track sequence indices and mapping keys, treat custom/global tags as metadata plus `yaml_custom_tag_unsupported`, and reject alias cycles before expanding them.

- [ ] **Step 7: Run adapter tests and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~StructuredPathTests
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~Structured
git add src/SecurityReview.Parsers/Structured tests/SecurityReview.UnitTests/Parsers/StructuredPathTests.cs tests/SecurityReview.ParserCorpusTests/Structured tests/Corpus/Structured
git commit -m "feat: parse structured files with bounded locations"
```

## Task P2-T2: Implement Open XML and visible macro-string parsing

**Files:**
- Create: `src/SecurityReview.Parsers/OpenXml/OpenXmlFormatParser.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/OpenXmlPackageGuard.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/WordContentReader.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/SpreadsheetContentReader.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/PresentationContentReader.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/PackageMetadataReader.cs`
- Create: `src/SecurityReview.Parsers/OpenXml/VbaVisibleStringReader.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/OpenXml/OpenXmlParserTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/OpenXml/OpenXmlSecurityTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/OpenXml/OpenXmlNoExecutionTests.cs`
- Create: `tests/Corpus/Office/generate-openxml-corpus.ps1`

**Interfaces:**
- Consumes: ZIP budget/virtual paths and `IFormatParser`.
- Produces: Word paragraph/comment/metadata locations, Excel Sheet/cell/formula/hidden metadata, PowerPoint slide/shape/note locations, embedded child events, and explicit legacy/OCR/macro coverage gaps.

- [ ] **Step 1: Generate and test a golden Office corpus**

Use Open XML SDK in the test generator to create deterministic DOCX, XLSX, PPTX, DOCM, XLSM, and PPTM fixtures. Include document properties, comments, headers/footers, footnotes/endnotes, hidden Sheet/row/column, shared/inline strings, formula text and cached value, slide notes, custom XML, external relationship descriptors, embedded text/ZIP, and a synthetic `vbaProject.bin` containing visible ASCII/UTF-16 canaries.

Add legacy `.doc/.xls/.ppt`, password-protected/encrypted package, corrupt ZIP, relationship traversal, oversized part, and external URL fixtures. Assert exact part/paragraph, Sheet/cell, slide/shape/note, or byte-offset locations; assert no external HTTP canary receives a request.

- [ ] **Step 2: Run Open XML tests and observe missing parser**

```powershell
pwsh tests/Corpus/Office/generate-openxml-corpus.ps1
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~OpenXml
```

Expected: FAIL because Open XML adapters do not exist.

- [ ] **Step 3: Guard the package before SDK traversal**

`OpenXmlPackageGuard` first treats the file as ZIP using the shared archive budget. It validates `[Content_Types].xml`, relationship target strings, normalized part URIs, duplicate/case-colliding part names, declared/compressed sizes, and maximum 10,000 parts. It rejects external relationship loading but emits the relationship type/target text as an untrusted metadata chunk. It never dereferences a target.

If OLE Compound File magic identifies legacy Office, emit one `UnsupportedFormat` gap with code `legacy_office_body_unsupported`; still feed filename/path and bounded raw binary strings to the P1 printable-string fallback. P2-T4 later adds PE/ELF-specific structure without changing this behavior.

- [ ] **Step 4: Implement read-only Word/Excel/PowerPoint readers**

Open the guarded seekable stream read-only. Iterate parts explicitly with `OpenXmlReader`/part streams rather than materializing `OpenXmlElement` trees or asking the SDK to auto-resolve external content. Count actual decompressed bytes against the shared archive budget on every part read; declared-size validation alone is insufficient.

- Word: main document, headers, footers, comments, footnotes, endnotes, glossary, custom XML text, core/extended/custom properties; locator is part URI + paragraph/run ordinal.
- Excel: every worksheet including hidden/very-hidden; shared strings, inline strings, cell values/formulas, comments/notes, row/column hidden flags, defined names, workbook/core/custom properties; locator is Sheet name + A1 cell or metadata key.
- PowerPoint: every slide, shape text, tables, notes, comments, masters/layout text, core/custom properties; locator is slide number + shape ID + paragraph/run ordinal.

Emit formulas as literal text and cached values as separate chunks. Do not calculate, open links, instantiate OLE/ActiveX, or call Office COM.

- [ ] **Step 5: Parse embedded parts and macro strings safely**

For an embedded part, reserve archive budget and emit `ChildDiscovered` only when it is a bounded ordinary byte stream; otherwise emit `UnsupportedRegion`. `VbaVisibleStringReader` scans `vbaProject.bin` for printable ASCII and UTF-16LE sequences of 6–1,048,576 characters and reports byte offsets. It does not parse VBA semantics, decompress modules, invoke a macro engine, or mark macro content fully covered; add `macro_semantics_not_analyzed` to coverage.

Encrypted/password-protected packages immediately emit `Encrypted`; do not accept or cache passwords.

- [ ] **Step 6: Add network/no-execution and formula assertions**

Run an HTTP canary, filesystem canary, and process-start monitor while parsing. Assert zero requests, zero child processes, no writes outside AppContainer private temp, formula text remains a string, and relationship targets are never opened. A malformed single part yields a part-scoped gap while other valid parts continue when the package API permits it.

- [ ] **Step 7: Run and commit**

```powershell
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~OpenXml
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~OpenXmlNoExecution
git add src/SecurityReview.Parsers/OpenXml tests/SecurityReview.ParserCorpusTests/OpenXml tests/Corpus/Office tests/SecurityReview.WindowsSecurityTests/OpenXml/OpenXmlNoExecutionTests.cs
git commit -m "feat: statically parse Open XML content and macro strings"
```

## Task P2-T3: Implement PDF text, metadata, and bounded attachment parsing

**Files:**
- Create: `src/SecurityReview.Parsers/Pdf/PdfFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Pdf/PdfPigAdapter.cs`
- Create: `src/SecurityReview.Parsers/Pdf/PdfCoverageClassifier.cs`
- Create: `src/SecurityReview.Parsers/Pdf/PdfAttachmentGuard.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Pdf/PdfParserTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Pdf/PdfAdversarialTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Pdf/PdfNoNetworkExecutionTests.cs`
- Create: `tests/Corpus/Pdf/generate-pdf-corpus.ps1`

**Interfaces:**
- Consumes: `IFormatParser`, child archive budget, PdfPig 0.1.14 behind `PdfPigAdapter`.
- Produces: page/block/metadata/attachment chunks plus image-only, encrypted, malformed, or unsafe-attachment gaps.

- [ ] **Step 1: Generate PDF golden and adversarial fixtures**

Create deterministic PDFs with ordered/unordered text, Chinese font text, metadata, annotations/link text, form field values, bookmarks, one safe text attachment, one image-only page, mixed text/image page, encrypted PDF, malformed xref/object stream, recursive page tree, excessive nesting, huge declared stream, and truncated tail. Location expectations use page number and stable block/word ordinal, not screen pixels.

- [ ] **Step 2: Write failing coverage tests**

Assert extractable text and metadata are chunks; image-only page yields `UnsupportedRegion` code `pdf_image_text_requires_ocr`; mixed page is partially covered; encrypted PDF yields `Encrypted` without password attempt; safe attachment becomes a virtual child; an attachment lacking a safely checkable bounded size yields `pdf_attachment_not_safely_extractable` rather than materialization.

- [ ] **Step 3: Implement the narrow PdfPig adapter**

Only `PdfPigAdapter` references PdfPig namespaces. It opens the handle-backed seekable stream read-only, iterates pages, uses `ContentOrderTextExtractor`/word extraction, reads document information, annotations/link display text, form values, and bookmarks. It maps all library exceptions to adapter error codes without returning raw exception text.

Page output is bounded to 10 MiB logical text and 1,000,000 letters; exceeding either records `ArchiveLimit` for the rest of that page. Do not render, execute JavaScript, open a hyperlink, resolve a remote font, or use shell/preview handlers.

- [ ] **Step 4: Implement page coverage classification**

For each page record `text_objects`, `image_objects`, extracted character count, and parser warnings. Classify:

- text objects and successful extraction: covered for extractable text;
- only images or zero text with images: not covered for image text/OCR;
- both text and images: partially covered, with an OCR gap for image regions;
- parser warning/exception after partial text: partially covered;
- encryption: not covered.

The scan summary must not simplify a mixed document to fully covered.

- [ ] **Step 5: Guard attachments before bytes are requested**

Inspect attachment metadata/declared stream length through the adapter. Extract only when declared length is present, non-negative, at most 64 MiB, and remaining archive budget accepts it. If PdfPig cannot provide size before materialization for a particular attachment, do not call its byte-returning API; emit a gap. Safe bytes are wrapped in a bounded stream, sniffed, and emitted as `ChildDiscovered` with `pdf!/attachment-name` virtual path.

- [ ] **Step 6: Run corpus under worker limits and commit**

```powershell
pwsh tests/Corpus/Pdf/generate-pdf-corpus.ps1
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~Pdf
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~Pdf
git add src/SecurityReview.Parsers/Pdf tests/SecurityReview.ParserCorpusTests/Pdf tests/Corpus/Pdf tests/SecurityReview.WindowsSecurityTests/Pdf/PdfNoNetworkExecutionTests.cs
git commit -m "feat: extract bounded PDF text and coverage gaps"
```

## Task P2-T4: Implement Python, JAR/JVM, PE/ELF, and generic binary parsing

**Files:**
- Create: `src/SecurityReview.Parsers/Text/PythonLexicalLocator.cs`
- Create: `src/SecurityReview.Parsers/Jvm/JvmClassParser.cs`
- Create: `src/SecurityReview.Parsers/Jvm/ModifiedUtf8Decoder.cs`
- Create: `src/SecurityReview.Parsers/Jvm/JarFormatParser.cs`
- Read: `src/SecurityReview.Parsers/Binary/PrintableStringExtractor.cs`
- Create: `src/SecurityReview.Parsers/Binary/PeMetadataParser.cs`
- Create: `src/SecurityReview.Parsers/Binary/ElfMetadataParser.cs`
- Create: `tests/SecurityReview.UnitTests/Parsers/JvmClassParserTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Binary/CodeAndBinaryParserTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Parsers/NoExecutionTests.cs`
- Create: `tests/Corpus/Jvm/generate-jvm-corpus.ps1`
- Create: `tests/Corpus/Binary/generate-binary-corpus.ps1`

**Interfaces:**
- Consumes: text parser, ZIP/JAR recursion, binary chunk/locator support.
- Produces: Python line/column lexical kinds, JAR nested paths/manifest/resources, JVM class/constant-pool index, and PE/ELF section/resource/string byte offsets.

- [ ] **Step 1: Write Python lexical location tests**

Generate `.py` with comments, normal/raw/bytes/f/triple strings, escaped newlines, non-ASCII identifiers, and an invalid tail. Assert the canary's file line/column and lexical kind. The parser reuses strict text decoding and does not import, compile, execute, discover environments, or resolve referenced files.

- [ ] **Step 2: Write JVM constant-pool boundary tests**

Fixtures cover valid class versions, `CONSTANT_Utf8`, `String`, `Class`, `NameAndType`, `Module`, `Package`, long/double two-slot entries, invalid magic, truncated lengths, unknown tags, huge declared UTF-8, malformed modified UTF-8, and a nested JAR. Assert class name, pool index, tag, byte offset, and exact nested `!/` path.

- [ ] **Step 3: Implement the class-file reader**

Read big-endian values from a bounded stream; verify `0xCAFEBABE`; accept class major versions listed in the signed parser policy; bound constant-pool count to 65,535 and each UTF-8 entry to 1 MiB. Parse only constant-pool/structural metadata required for strings and names. Do not interpret bytecode, resolve classes, load a JVM, or decompile methods. Unknown/invalid tags produce `Corrupt` at the pool index and stop that class.

`JarFormatParser` delegates ZIP safety, parses `META-INF/MANIFEST.MF` as text, emits entry names/resources, sends `.class` to `JvmClassParser`, and recursively handles nested archives within shared limits.

- [ ] **Step 4: Write binary extraction tests**

Generate minimal valid PE32+/ELF32/ELF64 files with canaries in headers, section names, resources/string sections and UTF-16LE data; add invalid offsets, overlapping sections, integer-overflow values, enormous counts, and random high-entropy bytes. Assert section/resource name and original byte offset. A parser error must still allow bounded generic string extraction from safe byte ranges and record an unsupported-region gap.

- [ ] **Step 5: Implement PE/ELF header and string adapters**

`PeMetadataParser` validates DOS/PE signatures, `e_lfanew`, COFF/optional header sizes, section count ≤96, all offset+length calculations with checked 64-bit arithmetic, resource recursion depth ≤16, and reads imports/version/resource names only inside declared file bounds.

`ElfMetadataParser` validates endian/class, header/section table bounds, section count ≤65,535, string-table ranges, note/build metadata and dynamic-needed names; it never disassembles.

Reuse the P1 `PrintableStringExtractor` unchanged as the safe fallback when structured PE/ELF parsing fails. It does not classify random binary as fully covered; PE/ELF unparsed regions remain stated in coverage.

- [ ] **Step 6: Run corpus and no-execution monitors, then commit**

```powershell
pwsh tests/Corpus/Jvm/generate-jvm-corpus.ps1
pwsh tests/Corpus/Binary/generate-binary-corpus.ps1
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Jvm
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter "FullyQualifiedName~Binary|FullyQualifiedName~Code"
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~NoExecution
git add src/SecurityReview.Parsers/Text/PythonLexicalLocator.cs src/SecurityReview.Parsers/Jvm src/SecurityReview.Parsers/Binary tests/Corpus/Jvm tests/Corpus/Binary tests/SecurityReview.UnitTests/Parsers/JvmClassParserTests.cs tests/SecurityReview.ParserCorpusTests/Binary/CodeAndBinaryParserTests.cs tests/SecurityReview.WindowsSecurityTests/Parsers/NoExecutionTests.cs
git commit -m "feat: statically inspect Python JVM and native binaries"
```

## Task P2-T5: Implement Docker archive and OCI image-layout parsing

**Files:**
- Create: `src/SecurityReview.Domain/Assets/OciDescriptor.cs`
- Create: `src/SecurityReview.Parsers/Oci/OciDigest.cs`
- Create: `src/SecurityReview.Parsers/Oci/OciJsonParser.cs`
- Create: `src/SecurityReview.Parsers/Oci/DockerArchiveParser.cs`
- Create: `src/SecurityReview.Parsers/Oci/OciLayerParser.cs`
- Create: `src/SecurityReview.Parsers/Oci/WhiteoutClassifier.cs`
- Create: `src/SecurityReview.Application/Scans/Oci/OciLayoutPlanner.cs`
- Create: `tests/SecurityReview.UnitTests/Oci/OciDigestTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Oci/OciParserTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Oci/DockerIndependenceTests.cs`
- Create: `tests/Corpus/Oci/generate-oci-corpus.ps1`

**Interfaces:**
- Consumes: trusted root inventory/broker, worker structured/TAR parsers, shared archive budget.
- Produces: validated manifest/config/layer plan, environment/label/history chunks, every layer entry including deleted history, and OCI locators.

- [ ] **Step 1: Generate Docker/OCI corpus and golden expectations**

Build synthetic OCI image layout and Docker-save TAR fixtures without Docker Desktop. Include single/multi-platform indexes, manifest/config, Env, Labels, Entrypoint/Cmd, History.created_by, two layers where layer 1 has a canary and layer 2 whiteouts it, opaque whiteout, duplicate path, symlink/hardlink, gzip layer, digest mismatch, missing blob, traversal path, unsupported media type, foreign URL, and corrupt layer.

Expected location is manifest digest + layer digest + zero-based layer index + internal path + entry offset. The deleted layer-1 canary remains a finding candidate and is marked `not_in_final_view`; it is not removed.

- [ ] **Step 2: Write digest, descriptor, and layer-order tests**

`OciDigest` accepts lowercase `sha256:<64 hex>` only in V1 and verifies bytes with fixed-time comparison. Descriptor size must equal brokered file length; media type must be an approved OCI/Docker manifest/config/layer type; URLs are metadata text only and never fetched. Multi-platform index preserves ordinal manifest list and requires every descriptor to be scheduled or explicitly gapped by policy limit.

- [ ] **Step 3: Implement two input modes without directory authority in worker**

- OCI directory: trusted `OciLayoutPlanner` identifies `oci-layout`/`index.json` inventory records, sends each JSON/blob handle to a worker for parse/hash, then requests the next exact `blobs/sha256/<digest>` record from the trusted broker. Worker never receives the directory root.
- Docker TAR: worker uses bounded TAR parsing, parses top-level `manifest.json` and config, and maps listed layer entry streams in declared order. It never contacts a daemon/socket/registry.

Reject any descriptor path not exactly derivable from a validated digest. Verify digest and size before parsing content.

- [ ] **Step 4: Parse config and every layer independently**

Emit structured chunks for architecture/OS, Env, Labels, Entrypoint, Cmd, WorkingDir, User, exposed ports, volumes, rootfs diff IDs, and every History entry. For each layer, parse all regular entries with TAR/link/traversal limits. `WhiteoutClassifier` annotates final-view status but never suppresses earlier chunks. Symlink/hardlink contents are not followed; link target text is scanned and a coverage note recorded.

- [ ] **Step 5: Validate multi-platform and failure semantics**

A missing/mismatched/corrupt blob produces a descriptor-scoped gap and Partial while other manifests/layers continue. Unsupported media type produces `UnsupportedRegion`. If a selected image contains no successfully parsed manifest, task-level asset parsing is not covered. No Docker executable/process/socket/file under standard Docker locations may be opened in the WindowsSecurity monitor.

- [ ] **Step 6: Run OCI corpus without Docker and commit**

```powershell
pwsh tests/Corpus/Oci/generate-oci-corpus.ps1
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~Oci
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~Oci
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~DockerIndependence
git add src/SecurityReview.Domain/Assets/OciDescriptor.cs src/SecurityReview.Parsers/Oci src/SecurityReview.Application/Scans/Oci tests/Corpus/Oci tests/SecurityReview.UnitTests/Oci/OciDigestTests.cs tests/SecurityReview.ParserCorpusTests/Oci/OciParserTests.cs tests/SecurityReview.WindowsSecurityTests/Oci/DockerIndependenceTests.cs
git commit -m "feat: scan Docker and OCI image history layers"
```

## Task P2-T6: Implement safe model metadata parsing

**Files:**
- Create: `src/SecurityReview.Parsers/Models/ModelFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Models/SafeTensorsHeaderParser.cs`
- Create: `src/SecurityReview.Parsers/Models/GgufMetadataParser.cs`
- Create: `src/SecurityReview.Parsers/Models/OnnxMetadataWireParser.cs`
- Create: `src/SecurityReview.Parsers/Models/DangerousModelFormatClassifier.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Models/ModelMetadataParserTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Models/ModelNoExecutionTests.cs`
- Create: `tests/Corpus/Models/generate-model-corpus.ps1`

**Interfaces:**
- Consumes: generic text/JSON/binary parsers and file/path chunks.
- Produces: safe header/metadata strings and explicit unparsed-weight/dangerous-serialization coverage gaps.

- [ ] **Step 1: Generate safe and dangerous model fixtures**

Create minimal Safetensors headers, GGUF v2/v3 metadata, ONNX protobuf metadata properties, adjacent `config.json`, tokenizer files and model card; add oversized header/count/string, integer overflow, truncated values, duplicate keys, pickle signatures (`.pt/.pth/.pkl`), unknown model magic, and canaries only in unparsed weight bytes.

Expected: safe metadata and adjacent files are scanned; weight tensors are not claimed semantically covered; pickle is never deserialized and produces `dangerous_object_serialization_not_loaded`; unknown model bytes receive bounded binary strings plus `model_weight_semantics_uncovered`.

- [ ] **Step 2: Implement strictly bounded header readers**

- Safetensors: read little-endian 64-bit JSON header length; require 2–100 MiB; verify header ends before file length; stream-parse JSON names/dtypes/shapes/metadata; do not read tensor payload except generic bounded strings when policy enables it.
- GGUF: verify magic/version, bound tensor/KV counts to 1,000,000, strings to 1 MiB, arrays to remaining budget, use checked offsets/alignment, emit key/value metadata and tensor names only.
- ONNX: implement a bounded protobuf wire walker for field numbers needed for model producer/domain/doc string/metadata properties and graph/node/input/output names; skip length-delimited tensor raw data by validated length. Do not instantiate an ONNX runtime.

- [ ] **Step 3: Add dangerous format classifier**

Match pickle protocols/magic and known PyTorch archive markers before generic archive recursion. Emit file/path/entry names and safe adjacent metadata, but do not hand pickle members to a Python/object deserializer. Mark the serialized object region NotCovered and task Partial.

- [ ] **Step 4: Run model corpus and memory assertions**

```powershell
pwsh tests/Corpus/Models/generate-model-corpus.ps1
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~ModelMetadata
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~ModelNoExecution
git add src/SecurityReview.Parsers/Models tests/SecurityReview.ParserCorpusTests/Models tests/Corpus/Models tests/SecurityReview.WindowsSecurityTests/Models/ModelNoExecutionTests.cs
git commit -m "feat: inspect safe model metadata without object loading"
```

## Task P2-T7: Establish the cross-format location and coverage corpus gate

**Files:**
- Create: `tests/Corpus/corpus-manifest.schema.json`
- Create: `tests/Corpus/corpus-manifest.json`
- Create: `tools/SecurityReview.CorpusTool/Commands/VerifyParserCorpusCommand.cs`
- Create: `tools/SecurityReview.CorpusTool/Model/CorpusExpectation.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Corpus/CorpusManifestTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Corpus/FullParserCorpusTests.cs`
- Create: `docs/operations/parser-support-matrix.md`

**Interfaces:**
- Consumes: all P1/P2 adapters and coverage events.
- Produces: one versioned machine-readable corpus manifest, parser support matrix, and P2 release gate consumed by P3/P6.

- [ ] **Step 1: Define a machine-readable expectation schema**

Each corpus case contains: case ID, generated fixture path, SHA-256, declared format, expected parser/version, expected chunks with value HMAC canary label and exact locator fields, expected gaps with reason/detail code/virtual path, maximum duration, maximum worker memory, and whether final coverage is Covered/Partial/NotCovered. The schema rejects unknown fields and duplicate case IDs.

- [ ] **Step 2: Add manifest integrity tests**

Tests regenerate fixtures, compare every fixture SHA-256 to the manifest, require at least one positive, negative, corrupt, encrypted/unsupported, limit, and crash case per adapter, and reject unreferenced committed corpus files. Generated private/adversarial corpora may use a separate signed local manifest but follow the same schema.

- [ ] **Step 3: Implement `verify-parser-corpus` command**

The command runs each case through the real sandbox worker, normalizes nondeterministic IDs/timestamps, compares parser events/locators/gaps exactly, enforces duration/memory, and writes only counts/case IDs/result codes to `artifacts/corpus/parser-results.json`. It must not write chunk text.

Command:

```powershell
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-parser-corpus --manifest tests/Corpus/corpus-manifest.json --output artifacts/corpus/parser-results.json
```

Expected: exit 0 and JSON summary with all cases passed. Any location or expected-gap mismatch exits 1.

- [ ] **Step 4: Generate the support matrix from code and manifest**

`parser-support-matrix.md` lists format, covered regions, partial/uncovered regions, parser/version, locator, limits, and corpus case IDs. Generate it from the parser registry plus manifest so documentation cannot silently claim unsupported coverage. Commit generated output only when its deterministic diff is reviewed.

- [ ] **Step 5: Run P2 gate and commit**

```powershell
pwsh ./build/test.ps1 -Lane ParserCorpus -RequireCorpus
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- verify-parser-corpus --manifest tests/Corpus/corpus-manifest.json --output artifacts/corpus/parser-results.json
dotnet format SecurityReviewTool.sln --verify-no-changes --no-restore
git add tests/Corpus tools/SecurityReview.CorpusTool tests/SecurityReview.ParserCorpusTests/Corpus docs/operations/parser-support-matrix.md
git commit -m "test: gate parser coverage and exact locations with corpus"
```

P2 is complete only when every corpus case resolves to all expected chunks and gaps, no unexpected gap is hidden, and the support matrix matches the tested adapter behavior.
