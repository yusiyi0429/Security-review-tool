# Security Review P1 Inventory and Parser Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn selected files/directories into a stable, root-bounded inventory and parse text and nested ZIP/TAR/GZip content through the proven sandbox while accounting for every planned unit and failure.

**Architecture:** Trusted Windows inventory code owns paths, file identities, hashes, ADS discovery, and duplicated read-only handles. Sandboxed workers own format sniffing and bounded streaming parse. The Application orchestrator connects both sides with a bounded scheduler, progress aggregation, cancellation, and an in-memory coverage ledger that P4 later persists.

**Tech Stack:** .NET 10, Windows file/reparse/stream APIs, SHA-256, `System.IO.Pipelines`, `System.Threading.Channels`, `System.IO.Compression`, `System.Formats.Tar`, parser protocol v1, xUnit.net v3.

## Global Constraints

- Never follow a reparse point outside the selected root; formal scans default to following none.
- Enumerate hidden/system files and NTFS alternate data streams; lack of ADS capability on non-NTFS is explicit coverage metadata.
- Hash content with SHA-256 and verify again after parsing; one mutation triggers one re-scan, a second triggers `FileUnstable`.
- Parse from duplicated read-only handles inside AppContainer; never grant worker root-directory authority.
- Stream content in at most 1 MiB chunks with 4 KiB overlap; large-file memory must not grow linearly.
- Archive depth is 5, entries 100,000/task, logical expansion 50 GiB or 100× input, and single entry 4 GiB.
- Cancellation stops new scheduling within 2 seconds and preserves already committed coverage evidence.

---

## Task P1-T1: Implement Manifest and scan-root configuration

**Files:**
- Create: `src/SecurityReview.Domain/Assets/AssetTypeId.cs`
- Create: `src/SecurityReview.Domain/Assets/CategoryId.cs`
- Create: `src/SecurityReview.Domain/Assets/AssetManifest.cs`
- Create: `src/SecurityReview.Domain/Assets/AssetComponent.cs`
- Create: `src/SecurityReview.Domain/Assets/ComplianceEvidence.cs`
- Create: `src/SecurityReview.Application/Scans/Preflight/IManifestReader.cs`
- Create: `src/SecurityReview.Infrastructure/Manifest/JsonManifestReader.cs`
- Create: `src/SecurityReview.Infrastructure/Manifest/ManifestJsonContext.cs`
- Create: `rules/schemas/security-asset-manifest-v1.schema.json`
- Create: `tests/SecurityReview.UnitTests/Assets/AssetManifestTests.cs`
- Create: `tests/SecurityReview.ContractTests/Manifest/ManifestContractTests.cs`
- Create: `tests/SecurityReview.ContractTests/Manifest/Fixtures/valid-minimal.json`
- Create: `tests/SecurityReview.ContractTests/Manifest/Fixtures/invalid-root-escape.json`

**Interfaces:**
- Consumes: scan preflight from P0-T5.
- Produces: `AssetManifest`, `ManifestSnapshot`, `IManifestReader.ReadAsync`, and validated component-to-asset mappings consumed by policy and inventory.

- [ ] **Step 1: Write failing domain validation tests**

```csharp
using SecurityReview.Domain.Assets;

namespace SecurityReview.UnitTests.Assets;

public sealed class AssetManifestTests
{
    [Theory]
    [InlineData("ASSET-001")]
    [InlineData("ASSET-011")]
    public void Accepts_registered_asset_type(string value) =>
        Assert.Equal(value, AssetTypeId.Parse(value).Value);

    [Theory]
    [InlineData("ASSET-000")]
    [InlineData("ASSET-012")]
    [InlineData("asset-001")]
    public void Rejects_unknown_asset_type(string value) =>
        Assert.Throws<ArgumentException>(() => AssetTypeId.Parse(value));

    [Theory]
    [InlineData("..\\outside")]
    [InlineData("C:\\absolute")]
    [InlineData("/absolute")]
    public void Rejects_component_path_outside_root(string path) =>
        Assert.Throws<ArgumentException>(() => AssetComponent.Create(path, AssetTypeId.Parse("ASSET-001")));
}
```

- [ ] **Step 2: Run focused tests and observe missing types**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~AssetManifestTests
```

Expected: FAIL because asset domain types do not exist.

- [ ] **Step 3: Implement stable registries and root-relative paths**

```csharp
namespace SecurityReview.Domain.Assets;

public readonly record struct AssetTypeId
{
    private static readonly HashSet<string> Allowed =
        Enumerable.Range(1, 11).Select(i => $"ASSET-{i:000}").ToHashSet(StringComparer.Ordinal);
    public string Value { get; }
    private AssetTypeId(string value) => Value = value;
    public static AssetTypeId Parse(string value) => Allowed.Contains(value)
        ? new(value) : throw new ArgumentException("Unknown asset type.", nameof(value));
}

public readonly record struct CategoryId
{
    private static readonly HashSet<string> Allowed =
        Enumerable.Range(1, 8).Select(i => $"SENS-{i:000}").ToHashSet(StringComparer.Ordinal);
    public string Value { get; }
    private CategoryId(string value) => Value = value;
    public static CategoryId Parse(string value) => Allowed.Contains(value)
        ? new(value) : throw new ArgumentException("Unknown category.", nameof(value));
}

public sealed record AssetComponent(string RelativePath, AssetTypeId AssetType)
{
    public static AssetComponent Create(string path, AssetTypeId type)
    {
        string normalized = path.Replace('\\', '/').Trim();
        if (string.IsNullOrEmpty(normalized)) normalized = ".";
        if (normalized == ".") return new(normalized, type);
        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        bool looksAbsolute = Path.IsPathRooted(path)
            || normalized.StartsWith('/', StringComparison.Ordinal)
            || normalized.StartsWith("//", StringComparison.Ordinal)
            || (normalized.Length >= 2 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':');
        if (looksAbsolute || segments.Any(x => x is "." or "..") || normalized.Contains('\0'))
            throw new ArgumentException("Component path must remain below the scan root.", nameof(path));
        return new(normalized, type);
    }
}
```

Define `AssetManifest` with schema version 1, non-empty asset ID/version, 1–1,000 non-overlapping component mappings, and structured compliance evidence statuses `Verified`, `DeclaredWithoutReference`, `NotApplicable`, `Unverifiable`. A declaration never suppresses content scanning.

- [ ] **Step 4: Write JSON contract tests**

Tests assert exact snake_case names, unknown top-level fields rejected, duplicate properties rejected, UTF-8 only, maximum 1 MiB, schema version exactly 1, maximum string 2,048 characters, maximum authorization entries 1,000, no absolute/root-escape paths, and deterministic SHA-256 of the original bytes. Missing Manifest returns `ManifestReadResult.NotFound`, not an exception.

Use this contract root:

```json
{
  "schema_version": 1,
  "asset_id": "synthetic-project",
  "asset_version": "1.0.0",
  "components": [{"path": ".", "asset_type": "ASSET-009"}],
  "compliance_evidence": {
    "knowledge_base_transformed": {"status": "not_applicable", "reference": null},
    "model_finetuned": {"status": "not_applicable", "reference": null},
    "third_party_authorizations": []
  }
}
```

- [ ] **Step 5: Implement bounded `JsonManifestReader`**

Open only `<selected-root>/security-asset-manifest.json` with read sharing, reject BOM other than UTF-8, read at most 1,048,577 bytes, parse with `Utf8JsonReader` using `CommentHandling=Disallow`, `AllowTrailingCommas=false`, `MaxDepth=16`, and explicitly track duplicate property names. Return stable validation errors containing JSON Pointer and code, never the value.

`ManifestSnapshot` contains the validated domain object, original SHA-256, `Found/Valid/Invalid`, and validation codes. UI overrides produce a separate immutable snapshot; do not write back to the asset.

- [ ] **Step 6: Run contract tests and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~AssetManifest
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release --filter FullyQualifiedName~Manifest
git add src/SecurityReview.Domain/Assets src/SecurityReview.Application/Scans/Preflight src/SecurityReview.Infrastructure/Manifest rules/schemas tests/SecurityReview.UnitTests/Assets tests/SecurityReview.ContractTests/Manifest
git commit -m "feat: validate asset manifest and component mappings"
```

## Task P1-T2: Implement root-bounded Windows inventory, ADS, and identity

**Files:**
- Create: `src/SecurityReview.Domain/Scans/FileRecord.cs`
- Create: `src/SecurityReview.Domain/Scans/FileStreamIdentity.cs`
- Create: `src/SecurityReview.Domain/Scans/InventoryMetadataUnit.cs`
- Create: `src/SecurityReview.Application/Scans/Inventory/IInventoryService.cs`
- Create: `src/SecurityReview.Application/Scans/Inventory/InventoryRequest.cs`
- Create: `src/SecurityReview.Application/Scans/Inventory/InventoryResult.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/WindowsInventoryService.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/ReparsePointInspector.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/AlternateDataStreamEnumerator.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/WindowsFileIdentityReader.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Files/WindowsInventoryServiceTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Inventory/InventoryCoverageTests.cs`

**Interfaces:**
- Consumes: validated root/component mappings and P0 coverage domain.
- Produces: ordered `FileRecord` inventory, bounded filename/path/ADS-name content units, root boundary decisions, ADS records, and inventory gaps consumed by hashing and scan orchestration.

- [ ] **Step 1: Write inventory acceptance tests**

Create an NTFS fixture containing ordinary, hidden, system, inaccessible, nested, symlink/junction-to-inside, symlink/junction-to-outside, and ADS entries. Assert:

```csharp
[Fact]
public async Task Enumerates_hidden_system_and_ads_without_following_reparse_points()
{
    InventoryResult result = await _service.BuildAsync(_fixture.Request, CancellationToken.None);
    Assert.Contains(result.Files, x => x.RelativePath == "hidden.txt");
    Assert.Contains(result.Files, x => x.RelativePath == "system.txt");
    Assert.Contains(result.Files, x => x.StreamName == "review-canary");
    Assert.DoesNotContain(result.Files, x => x.RelativePath.StartsWith("outside/", StringComparison.Ordinal));
    Assert.Contains(result.Gaps, x => x.Reason == GapReason.AccessDenied);
}

[Fact]
public async Task Ordering_is_ordinal_and_stable()
{
    InventoryResult first = await _service.BuildAsync(_fixture.Request, CancellationToken.None);
    InventoryResult second = await _service.BuildAsync(_fixture.Request, CancellationToken.None);
    Assert.Equal(first.Files.Select(x => x.InventoryKey), second.Files.Select(x => x.InventoryKey));
}
```

Add canaries that exist only in a directory name, file name, extension, and ADS name. Assert one `InventoryMetadataUnit` per canonical relative path, final file name, extension, and named stream with a reproducible `PathLocator`; hidden/system metadata is not omitted. Metadata values over 4,096 UTF-16 code units or with invalid Unicode form a gap instead of an unbounded chunk.

- [ ] **Step 2: Run Windows tests and observe failure**

```powershell
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~WindowsInventoryServiceTests
```

Expected: FAIL because inventory services do not exist.

- [ ] **Step 3: Implement stable file identity and record**

`FileStreamIdentity` contains volume serial, 128-bit file ID from `GetFileInformationByHandleEx(FileIdInfo)`, and optional ADS name. `FileId` is a task-local UUID derived with UUIDv5 from `scanId + volume + fileId + streamName`, while the database later stores an HMAC path fingerprint separately.

`FileRecord` fields are `FileId`, root ID, normalized relative path, encrypted-path placeholder, stream name, length, last-write UTC, attributes, identity, component asset types, inventory status, format ID, SHA-256, and coverage status. Do not use path alone as identity. `InventoryMetadataUnit` contains file ID, closed kind (`RelativePath`, `DirectorySegment`, `FileName`, `Extension`, `AdsName`), bounded value, and `PathLocator`; it is content for detection but never sent to the parser worker.

- [ ] **Step 4: Implement explicit stack traversal and reparse refusal**

`WindowsInventoryService` uses an explicit stack, not recursive calls. For each directory entry:

1. normalize and verify it remains under the canonical root;
2. read attributes without following the target;
3. if `ReparsePoint`, inspect tag and add a `reparse_point_not_followed` information/gap record; do not recurse in V1 formal mode;
4. include hidden/system entries;
5. open ordinary files using `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` for identity verification;
6. enumerate ADS with `FindFirstStreamW/FindNextStreamW`, exclude only the default `::$DATA` stream duplicate, and create one `FileRecord` per named data stream;
7. detect duplicate `(volume,fileId,stream)` to avoid cycles;
8. sort final records by root index, ordinal relative path, then ordinal stream name.

Access errors become typed gaps. If the selected root itself cannot be identified/enumerated, return task-level failure rather than a partial empty inventory.

Count ordinary files plus named ADS as planned streams and sum broker-reported lengths with checked 64-bit arithmetic. Once the task exceeds 100,000 streams or 10 GiB, stop before parser scheduling and return `input_scope_exceeded` with the observed count/bytes only; do not silently truncate into a seemingly valid Partial scan. Tests cover exact-boundary acceptance, one-over rejection, sparse 10 GiB input, and integer-overflow metadata. The UI instructs the user to split the release asset.

- [ ] **Step 5: Cover non-NTFS and long-path behavior**

Tests create a >260-character path using long-path-aware APIs, verify inventory succeeds on supported policy, and verify full internal paths never enter diagnostic messages. On a non-NTFS fixture, `AdsCapability=NotAvailableForFileSystem` appears in scan summary; the service does not claim ADS coverage.

- [ ] **Step 6: Run focused lanes and commit**

```powershell
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~Files
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~Inventory
git add src/SecurityReview.Domain/Scans src/SecurityReview.Application/Scans/Inventory src/SecurityReview.Infrastructure/Windows/Files tests/SecurityReview.WindowsSecurityTests/Files tests/SecurityReview.IntegrationTests/Inventory
git commit -m "feat: inventory Windows files streams and reparse boundaries"
```

## Task P1-T3: Implement stable hashing and the read-only file broker

**Files:**
- Create: `src/SecurityReview.Application/Scans/Inventory/IFileSnapshotService.cs`
- Create: `src/SecurityReview.Application/Scans/Inventory/FileSnapshot.cs`
- Create: `src/SecurityReview.Application/Scans/Inventory/FileStabilityDecision.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/WindowsFileSnapshotService.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/WindowsReadOnlyFileBroker.cs`
- Create: `src/SecurityReview.Infrastructure/Windows/Files/FileOpenRetryPolicy.cs`
- Create: `src/SecurityReview.Infrastructure/Hashing/Sha256StreamHasher.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/FileStabilityDecisionTests.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/FileOpenRetryPolicyTests.cs`
- Create: `tests/SecurityReview.WindowsSecurityTests/Files/WindowsReadOnlyFileBrokerTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Inventory/FileMutationTests.cs`

**Interfaces:**
- Consumes: `FileRecord`, Windows file identity, and P0 handle broker.
- Produces: `FileSnapshotService.OpenAndHashAsync`, immutable pre/post snapshots, one-retry stability decision, and an owned `BrokeredReadHandle` for sandbox launch.

- [ ] **Step 1: Write the mutation decision tests**

```csharp
[Theory]
[InlineData(true, 0, FileStabilityAction.Accept)]
[InlineData(false, 0, FileStabilityAction.RescanOnce)]
[InlineData(false, 1, FileStabilityAction.MarkUnstable)]
public void Chooses_bounded_mutation_action(bool hashesEqual, int priorRetries, FileStabilityAction expected)
{
    Assert.Equal(expected, FileStabilityDecision.Decide(hashesEqual, priorRetries));
}
```

Run and expect missing types.

With an injected clock, assert file-open retries occur only for `ERROR_SHARING_VIOLATION`/`ERROR_LOCK_VIOLATION` after 100 ms, 300 ms, and 900 ms (initial attempt plus three retries); success stops the sequence, cancellation stops immediately, and access-denied/not-found/path/reparse errors do not retry.

- [ ] **Step 2: Implement streaming SHA-256 and immutable snapshots**

`Sha256StreamHasher.ComputeAsync` rents a 128 KiB buffer from `ArrayPool<byte>`, calls `IncrementalHash.AppendData`, clears the used span before returning it, and never reads beyond the handle's declared length. `FileSnapshot` contains identity, length, last-write UTC, SHA-256 lowercase hex, and captured UTC.

Use constant-time byte comparison for hashes. A changed timestamp with identical SHA-256 remains stable but is recorded as metadata change; changed identity, length, or SHA-256 is content instability.

- [ ] **Step 3: Implement brokered read-only open**

Open files with `GENERIC_READ`, share `READ|WRITE|DELETE`, `OPEN_EXISTING`, `FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN`, and no write/delete access. Immediately query identity and size from the handle, not path. `BrokeredReadHandle` owns `SafeFileHandle`, initial snapshot, and redacted display ID. Only Infrastructure can expose the raw numeric handle to `DuplicateHandle`.

For ADS, construct the stream path only in the trusted broker after validating the enumerated stream name contains no separator, colon beyond its syntax, or NUL.

Wrap the native open in `FileOpenRetryPolicy`; after the final sharing/lock failure, record a typed access/read gap and continue the task. Retry events expose attempt/error code/delay only—never path or file name.

- [ ] **Step 4: Add real mutation tests**

Use a barrier-controlled synthetic writer to mutate a file after initial hash and during parse. Assert first change produces exactly one new parse job; a second change produces `GapReason.FileUnstable`, final task Partial, and no “resolved” finding for that file. Also assert replacement-by-rename changes file identity even if length/timestamp match.

- [ ] **Step 5: Run and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~FileStability|FullyQualifiedName~FileOpenRetry"
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.WindowsSecurityTests/SecurityReview.WindowsSecurityTests.csproj -c Release --filter FullyQualifiedName~ReadOnlyFileBroker
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~FileMutation
git add src/SecurityReview.Application/Scans/Inventory src/SecurityReview.Infrastructure/Windows/Files src/SecurityReview.Infrastructure/Hashing tests/SecurityReview.UnitTests/Scans/FileStabilityDecisionTests.cs tests/SecurityReview.UnitTests/Scans/FileOpenRetryPolicyTests.cs tests/SecurityReview.WindowsSecurityTests/Files/WindowsReadOnlyFileBrokerTests.cs tests/SecurityReview.IntegrationTests/Inventory/FileMutationTests.cs
git commit -m "feat: bind scans to stable read-only file snapshots"
```

## Task P1-T4: Implement format sniffing, strict encoding, and text chunks

**Files:**
- Create: `src/SecurityReview.Parsers/Core/FormatProbe.cs`
- Create: `src/SecurityReview.Parsers/Core/IFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Core/FormatSniffer.cs`
- Create: `src/SecurityReview.Parsers/Core/ParserInput.cs`
- Create: `src/SecurityReview.Parsers/Core/ParseContext.cs`
- Create: `src/SecurityReview.Parsers/Core/ParserEvent.cs`
- Create: `src/SecurityReview.Parsers/Core/ContentChunker.cs`
- Create: `src/SecurityReview.Parsers/Text/TextEncodingDetector.cs`
- Create: `src/SecurityReview.Parsers/Text/StreamingLineMap.cs`
- Create: `src/SecurityReview.Parsers/Text/TextFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Binary/PrintableStringExtractor.cs`
- Create: `tests/SecurityReview.UnitTests/Parsers/FormatSnifferTests.cs`
- Create: `tests/SecurityReview.UnitTests/Parsers/PrintableStringExtractorTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Text/TextParserTests.cs`
- Create: `tests/Corpus/Text/generate-text-corpus.ps1`

**Interfaces:**
- Consumes: parser contract DTOs and handle-backed `ParserInput`.
- Produces: `IFormatParser`, `FormatSniffer`, `TextFormatParser`, `ContentChunker`, bounded binary printable strings, and exact line/column/byte maps used by all later parsers.

- [ ] **Step 1: Write magic-over-extension tests**

Assert ZIP magic named `.txt` selects ZIP; PDF magic named `.json` selects PDF; ELF/PE/JVM class magic wins; valid UTF-8 without magic selects text; NUL-heavy/high-binary content selects binary; inconsistent extension creates `format_extension_mismatch` metadata without blocking parse.

- [ ] **Step 2: Implement bounded probe**

`FormatSniffer.ProbeAsync` reads at most the first 64 KiB and, when required, a bounded tail segment for ZIP/PDF markers using the seekable handle. It returns `DetectedFormat`, confidence, signature evidence codes, and mismatch flag. It recognizes ZIP/JAR/OpenXML by package entries only after archive parsing; extension is a hint, never authority.

- [ ] **Step 3: Write encoding and locator tests**

Generate the same Chinese canary text at test runtime as UTF-8, UTF-8 BOM, UTF-16LE/BE, and GB18030. Assert identical logical text, recorded encoding, line 2/column 3 locator, original byte range, and detection across a 1 MiB chunk boundary. Create malformed sequences and assert `DecodeUnreliable` rather than replacement-character acceptance.

Also generate ASCII/UTF-16 strings split across binary windows, too-short runs, invalid surrogate data, and random high-entropy bytes. Assert exact byte offsets, one de-duplicated boundary result, bounded output, and a remaining generic-binary coverage gap.

- [ ] **Step 4: Implement strict encoding selection**

At worker startup call `Encoding.RegisterProvider(CodePagesEncodingProvider.Instance)` exactly once. Detection order:

1. BOM-confirmed UTF-8/UTF-16LE/UTF-16BE;
2. strict UTF-8 decoder with `throwOnInvalidBytes=true`;
3. UTF-16 zero-byte distribution heuristic followed by strict decode;
4. strict GB18030 decoder (`Encoding.GetEncoding(54936, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback)`);
5. otherwise emit `DecodeUnreliable` with bytes processed and no lossy text.

Record the chosen encoding name. Do not normalize Unicode before preserving source location; detectors may create a normalized comparison copy later.

- [ ] **Step 5: Implement chunk and location invariants**

`ContentChunker` starts with a 512 KiB UTF-8 text target, carries up to 4,096 source bytes/characters of overlap, and measures the **entire source-generated serialized protocol envelope**. If JSON escaping/metadata/location maps would exceed 1,048,576 bytes, shrink at a Unicode-scalar boundary until the complete frame fits; never rely on text byte count alone. Coalesce linear location runs, cap maps at 8,192 sorted/non-overlapping entries, and shrink the chunk rather than drop mapping data. It emits monotonically increasing sequence numbers, original source byte ranges, and `IsFinal`. Deduplication later uses source location; the parser does not suppress overlap.

Use `ArrayPool<byte>`/`ArrayPool<char>` and clear used ranges before return. A single logical line longer than a chunk is split with continuous column/byte mapping.

`PrintableStringExtractor` scans fixed 1 MiB windows for ASCII and UTF-16LE/BE runs of at least 6 characters, caps one logical run at 1 MiB, preserves byte offsets, overlaps 16 bytes between windows, and emits an explicit generic-binary coverage gap for all other bytes. It is a fallback extractor, never evidence that a binary is fully covered.

- [ ] **Step 6: Run corpus tests and commit**

```powershell
pwsh tests/Corpus/Text/generate-text-corpus.ps1
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~FormatSniffer|FullyQualifiedName~PrintableString"
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~TextParser
git add src/SecurityReview.Parsers/Core src/SecurityReview.Parsers/Text src/SecurityReview.Parsers/Binary/PrintableStringExtractor.cs tests/SecurityReview.UnitTests/Parsers tests/SecurityReview.ParserCorpusTests/Text tests/Corpus/Text
git commit -m "feat: stream strict text chunks with exact locations"
```

## Task P1-T5: Implement bounded ZIP, TAR, and GZip recursion

**Files:**
- Create: `src/SecurityReview.Parsers/Archives/VirtualPath.cs`
- Create: `src/SecurityReview.Parsers/Archives/ArchiveBudget.cs`
- Create: `src/SecurityReview.Parsers/Archives/ArchiveEntryGuard.cs`
- Create: `src/SecurityReview.Parsers/Archives/ZipFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Archives/TarFormatParser.cs`
- Create: `src/SecurityReview.Parsers/Archives/GZipFormatParser.cs`
- Create: `tests/SecurityReview.UnitTests/Parsers/ArchiveBudgetTests.cs`
- Create: `tests/SecurityReview.ParserCorpusTests/Archives/ArchiveSafetyTests.cs`
- Create: `tests/Corpus/Archives/generate-archive-corpus.ps1`

**Interfaces:**
- Consumes: `IFormatParser`, `ParserEvent.ChildDiscovered`, `ParseLimits`, and text/binary sniffing.
- Produces: safe virtual children with `outer!/inner` paths and budget/gap events used recursively by the worker host.

- [ ] **Step 1: Write budget and path rejection tests**

Test depth 5 accepted/depth 6 rejected; entry 100,000 accepted/100,001 rejected; 4 GiB accepted/one byte above rejected; 100× accepted/greater rejected; 50 GiB aggregate cap; absolute, drive, UNC, NUL, empty, `.`, `..`, alternate separator and percent-encoded escape names rejected after canonicalization.

- [ ] **Step 2: Implement shared atomic archive budget**

Construct one task-wide budget with `maxExpandedBytes = min(50 GiB, saturatingMultiply(totalBrokeredInputBytes, 100))`, maximum 100,000 archive entries, maximum depth 5, and maximum 4 GiB for one entry. Zero-byte input permits metadata inspection but no expanded payload. `ArchiveBudget.TryReserve(entryCount, declaredBytes, compressedBytes, depth)` uses `Interlocked` operations and rolls back all counters when any limit fails. It tracks entries and expanded bytes across the entire task, not per archive. For formats without compressed length, count actual decompressed bytes and stop before the next write when the limit would be exceeded. Use checked/saturating 64-bit arithmetic for every sum/product; an overflow attempt is an `ArchiveLimit` gap.

`VirtualPath.ParseEntry` normalizes `/` and `\`, rejects root/escape segments, NUL/unpaired-surrogate input, and any composed path over 4,096 UTF-16 code units; it preserves the original bounded display name and builds `outer!/inner` without touching the filesystem. An over-limit/invalid name produces a typed entry-name gap and is never passed to a filesystem API.

- [ ] **Step 3: Write malicious corpus tests**

Generate ZIP/TAR/GZip fixtures for nested valid content, traversal, absolute path, duplicate name, case collision, symlink, hardlink, sparse/declared huge TAR entry, corrupt central directory/header, high compression ratio, depth 6, over-entry count using compact generated metadata, and nested ZIP-in-JAR. Assert every dangerous branch produces exactly one typed `ArchiveLimit`/`Corrupt`/`UnsupportedRegion` gap and valid siblings still parse.

- [ ] **Step 4: Implement no-extract archive adapters**

Use `ZipArchive` read mode and `TarReader`; never call `ExtractToDirectory`, `ExtractToFile`, or create a path from an entry name. Open each regular entry as a bounded stream, reserve budget, sniff it, and emit `ChildDiscovered` with a stream factory valid only during the parent job. TAR symbolic/hard links emit metadata chunks and `UnsupportedRegion`; they are never followed. GZip emits one virtual child using sanitized header name or `<gzip-content>`.

Duplicate/case-colliding entries each remain distinct by ordinal entry index; locations include entry index. Encrypted ZIP entries become `Encrypted`; no password API is invoked.

- [ ] **Step 5: Run safety corpus and commit**

```powershell
pwsh tests/Corpus/Archives/generate-archive-corpus.ps1
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter FullyQualifiedName~ArchiveBudget
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter FullyQualifiedName~ArchiveSafety
git add src/SecurityReview.Parsers/Archives tests/SecurityReview.UnitTests/Parsers/ArchiveBudgetTests.cs tests/SecurityReview.ParserCorpusTests/Archives tests/Corpus/Archives
git commit -m "security: bound recursive archive parsing"
```

## Task P1-T6: Implement worker pool, scan orchestration, progress, cancellation, and coverage ledger

**Files:**
- Create: `src/SecurityReview.Application/Scans/ICoverageLedger.cs`
- Create: `src/SecurityReview.Application/Scans/IScanOrchestrator.cs`
- Create: `src/SecurityReview.Application/Scans/InMemoryCoverageLedger.cs`
- Create: `src/SecurityReview.Application/Scans/ScanProgress.cs`
- Create: `src/SecurityReview.Application/Scans/ProgressAggregator.cs`
- Create: `src/SecurityReview.Application/Scans/ScanScheduler.cs`
- Create: `src/SecurityReview.Application/Scans/InventoryMetadataChunkAdapter.cs`
- Create: `src/SecurityReview.Application/Scans/ParserWorkerPool.cs`
- Create: `src/SecurityReview.Application/Scans/ScanOrchestrator.cs`
- Create: `src/SecurityReview.Worker/WorkerHost.cs`
- Create: `src/SecurityReview.Worker/ParserRegistry.cs`
- Create: `tools/SecurityReview.CorpusTool/Commands/ScanSmokeCommand.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/ScanSchedulerTests.cs`
- Create: `tests/SecurityReview.UnitTests/Scans/ProgressAggregatorTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Scans/TextArchiveScanTests.cs`
- Create: `tests/SecurityReview.IntegrationTests/Scans/CancellationTests.cs`

**Interfaces:**
- Consumes: preflight, inventory, broker, worker launcher, parser protocol, text/archive parser events.
- Produces: `IScanOrchestrator`, progress stream, cancellation behavior, terminal coverage summary, and a smoke-scan CLI used by every later phase.

- [ ] **Step 1: Write scheduler and cancellation tests**

Use deterministic fake workers and a fake clock. Assert maximum worker count `min(4,max(2,logicalCpu/2))`, at most one active scan, bounded queue capacity 128, ordinary parse deadline 120 seconds, Docker/OCI top-level deadline 30 minutes in one exclusive worker, no scheduling after cancellation request, retry only for file mutation (once), worker crash creates a gap and continues, and final status derives from the ledger.

Cancellation test records enqueue timestamps and asserts no new job begins more than 2 seconds after cancellation; current workers receive `CancelJob`, then Job termination after a 1-second grace.

- [ ] **Step 2: Implement bounded channels and worker lifecycle**

`ScanScheduler` uses `Channel<ScanWorkItem>` with `BoundedChannelFullMode.Wait`, capacity 128, single writer, multiple readers. `ParserWorkerPool` starts at most the configured count, recycles a worker after 100 files, any crash/protocol violation, or 30 minutes, and never reuses a worker after cancellation/timeout.

Set an absolute `ParseLimits.DeadlineUtc` of start+120 seconds for an ordinary file and start+30 minutes for a top-level Docker/OCI job. Heartbeats arrive at most every 5 seconds; three missed heartbeats trigger a liveness probe, but only the absolute deadline/cancel/process exit decides timeout. OCI work acquires an exclusive scheduler lease, drains ordinary active workers, and uses the OCI child-Job profile; release policy may lower but never raise these signed maxima.

Map worker results exactly:

```csharp
public static GapReason MapFailure(WorkerFailure failure) => failure switch
{
    WorkerFailure.Timeout => GapReason.ParserTimeout,
    WorkerFailure.MemoryLimit => GapReason.ParserMemory,
    WorkerFailure.ProtocolViolation => GapReason.ParserProtocolMismatch,
    WorkerFailure.Crash => GapReason.ParserCrash,
    WorkerFailure.Cancelled => GapReason.Cancelled,
    _ => GapReason.Corrupt
};
```

- [ ] **Step 3: Implement coverage ledger invariants**

Before scheduling, register every inventory stream, each inventory metadata unit, and each archive child as a planned unit. `InventoryMetadataChunkAdapter` converts metadata to validated in-process `ContentChunk` values with `ContentKind.PathMetadata`, deterministic job/sequence IDs and `PathLocator`; these chunks run through the trusted detector sink and never cross into a worker. File bodies run through workers. A unit can transition once from `Planned` to `Covered`, `PartiallyCovered`, or `NotCovered`; duplicate terminal events throw and fail the job. Final reconciliation compares planned IDs to terminal IDs and creates an internal `coverage_reconciliation_failed` task failure if any are missing.

- [ ] **Step 4: Implement progress aggregation without sensitive paths**

`ScanProgress` contains stage, discovered/processed/failed counts, planned/processed bytes, archive entry counts, finding count placeholder, LLM queue placeholder, active worker count, and a redacted current file ordinal. Coalesce updates to at most every 250 ms and at least every 500 ms while active. Do not expose absolute/relative path or content in progress events.

- [ ] **Step 5: Implement `ScanOrchestrator.RunAsync` sequence**

Sequence: transition Preflight; validate sandbox/rules/root/temp; build inventory; register planned units; transition Running; schedule brokered parse jobs; validate/store chunks through a no-op detector sink; post-read hash; bounded mutation retry; reconcile ledger; choose Completed/Partial; transition terminal. Task-level root/integrity/storage failures transition Failed. Always close Jobs and clean task temp in `finally`.

- [ ] **Step 6: Add end-to-end smoke and failure tests**

`ScanSmokeCommand` accepts `--root`, writes only JSON counts/status/hashes to stdout, and refuses to display chunks. Integration fixtures cover valid text, nested archive, corrupt sibling, worker crash canary, exclusion, mutation, and cancel. Expected statuses: all-valid Completed; any corrupt/excluded/crash/mutation-twice Partial; root unavailable Failed; user cancellation Cancelled.

- [ ] **Step 7: Run P1 gate and commit**

```powershell
dotnet test tests/SecurityReview.UnitTests/SecurityReview.UnitTests.csproj -c Release --filter "FullyQualifiedName~Scans|FullyQualifiedName~Parsers"
dotnet test tests/SecurityReview.ContractTests/SecurityReview.ContractTests.csproj -c Release
dotnet test tests/SecurityReview.ParserCorpusTests/SecurityReview.ParserCorpusTests.csproj -c Release --filter "FullyQualifiedName~Text|FullyQualifiedName~Archive"
$env:SECURITY_REVIEW_RUN_WINDOWS_SECURITY = "1"
dotnet test tests/SecurityReview.IntegrationTests/SecurityReview.IntegrationTests.csproj -c Release --filter FullyQualifiedName~Scans
dotnet run --project tools/SecurityReview.CorpusTool -c Release -- scan-smoke --root tests/Corpus/Text
git add src/SecurityReview.Application/Scans src/SecurityReview.Worker tools/SecurityReview.CorpusTool/Commands/ScanSmokeCommand.cs tests/SecurityReview.UnitTests/Scans/ScanSchedulerTests.cs tests/SecurityReview.UnitTests/Scans/ProgressAggregatorTests.cs tests/SecurityReview.IntegrationTests/Scans/TextArchiveScanTests.cs tests/SecurityReview.IntegrationTests/Scans/CancellationTests.cs
git commit -m "feat: orchestrate bounded local parsing with coverage accounting"
```

Expected smoke output contains `status`, counts, and fingerprints only; no file content or full path. P1 is complete when valid text/archive input can reach Completed and every injected failure reaches the exact non-success status/gap without terminating the coordinator.
