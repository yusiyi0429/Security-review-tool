using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;
using SecurityReview.Parsers.Text;

namespace SecurityReview.UnitTests.Parsers;

public sealed class ContentChunkSplitterTests
{
    // 16 chars per unit; the double serialization inflates one unit to ~58
    // frame bytes (CJK -> \\uXXXX x2 escaping, \" and \\ up to 4x), so 20,000
    // units produce a ~1.16 MB frame that must be split.
    private const string EscapeDenseUnit = "中文密钥=\\\"SECRET\\\"；";
    private const int OversizeRepeats = 20_000;

    private static readonly ScanId TestScanId = new(Guid.NewGuid());
    private static readonly JobId TestJobId = new(Guid.NewGuid());

    [Fact]
    public void oversize_cjk_escape_dense_text_splits_until_every_frame_fits()
    {
        string text = BuildOversizeText();
        ContentChunk chunk = MakeChunk(text);
        Assert.True(MeasureFrameBytes(chunk) > ContentChunkSplitter.MaxChunkFrameBytes);

        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(chunk);

        Assert.True(pieces.Count > 1);
        foreach (ContentChunk piece in pieces)
        {
            int frameBytes = MeasureFrameBytes(piece);
            Assert.True(frameBytes <= ContentChunkSplitter.MaxChunkFrameBytes,
                $"piece frame is {frameBytes} bytes");
            Assert.True(frameBytes <= ProtocolConstants.MaxFrameBytes);
        }
    }

    [Fact]
    public void split_pieces_concatenate_back_to_original_text()
    {
        string text = BuildOversizeText();
        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(MakeChunk(text));

        Assert.Equal(text, string.Concat(pieces.Select(p => p.Text)));
    }

    [Fact]
    public void split_pieces_keep_metadata_and_final_flag_on_last_piece_only()
    {
        string text = BuildOversizeText();
        ContentChunk chunk = MakeChunk(text, isFinal: true);
        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(chunk);

        Assert.True(pieces.Count > 1);
        for (int i = 0; i < pieces.Count; i++)
        {
            ContentChunk piece = pieces[i];
            Assert.Equal(chunk.JobId, piece.JobId);
            Assert.Equal(chunk.Sequence, piece.Sequence);
            Assert.Equal(chunk.VirtualPath, piece.VirtualPath);
            Assert.Equal(chunk.FormatId, piece.FormatId);
            Assert.Equal(chunk.ContentKind, piece.ContentKind);
            Assert.Equal(chunk.Encoding, piece.Encoding);
            Assert.Equal(chunk.ProtocolVersion, piece.ProtocolVersion);
            Assert.Equal(i == pieces.Count - 1, piece.IsFinal);
        }
    }

    [Fact]
    public void non_final_chunk_produces_only_non_final_pieces()
    {
        string text = BuildOversizeText();
        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(MakeChunk(text, isFinal: false));

        Assert.True(pieces.Count > 1);
        Assert.All(pieces, piece => Assert.False(piece.IsFinal));
    }

    [Fact]
    public void ascii_text_within_threshold_is_not_split()
    {
        var chunk = MakeChunk(new string('a', 100_000));

        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(chunk);

        Assert.Single(pieces);
        Assert.Same(chunk, pieces[0]);
    }

    [Fact]
    public void split_never_breaks_surrogate_pairs()
    {
        var builder = new StringBuilder();
        for (int i = 0; i < 30_000; i++)
            builder.Append("😀中\"😀");
        string text = builder.ToString();

        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(MakeChunk(text));

        Assert.True(pieces.Count > 1);
        foreach (ContentChunk piece in pieces)
        {
            Assert.False(char.IsLowSurrogate(piece.Text[0]));
            Assert.False(char.IsHighSurrogate(piece.Text[^1]));
        }

        Assert.Equal(text, string.Concat(pieces.Select(p => p.Text)));
    }

    [Fact]
    public void split_rebases_location_map_and_pieces_validate()
    {
        string text = BuildOversizeText();
        List<LocationMapEntry> map = BuildRunMap(text);
        var chunk = MakeChunk(text, map: map);
        long declaredLength = Encoding.UTF8.GetByteCount(text);

        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(chunk);

        Assert.True(pieces.Count > 1);
        long totalMappedChars = 0;
        foreach (ContentChunk piece in pieces)
        {
            Assert.Empty(piece.Validate(declaredLength));
            totalMappedChars += piece.LocationMap.Sum(e => e.TextLength);
        }

        // Clipping a contiguous tiling map must not lose or duplicate coverage.
        Assert.Equal((long)text.Length, totalMappedChars);
    }

    [Fact]
    public void split_advances_source_ranges_by_utf8_byte_counts()
    {
        string text = BuildOversizeText();
        var chunk = MakeChunk(text);
        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(chunk);

        long expectedStart = chunk.SourceStart;
        foreach (ContentChunk piece in pieces)
        {
            Assert.Equal(expectedStart, piece.SourceStart);
            Assert.Equal((long)Encoding.UTF8.GetByteCount(piece.Text), piece.SourceLength);
            expectedStart += piece.SourceLength;
        }

        Assert.Equal(chunk.SourceStart + chunk.SourceLength, expectedStart);
    }

    [Fact]
    public void rebase_location_map_clips_crossing_entries_and_drops_outside_entries()
    {
        LocationMapEntry[] map =
        [
            new LocationMapEntry(0, 100, 0, 100),
            new LocationMapEntry(100, 100, 100, 100),
            new LocationMapEntry(200, 100, 200, 100),
        ];

        IReadOnlyList<LocationMapEntry> rebased =
            ContentChunkSplitter.RebaseLocationMap(map, textWindowStart: 50, textWindowLength: 100);

        Assert.Equal(2, rebased.Count);
        Assert.Equal(new LocationMapEntry(50, 50, 0, 50), rebased[0]);
        Assert.Equal(new LocationMapEntry(100, 50, 50, 50), rebased[1]);
    }

    [Fact]
    public void rebase_location_map_keeps_zero_length_anchors_inside_window()
    {
        LocationMapEntry[] map =
        [
            new LocationMapEntry(400, 10, 30, 0),
            new LocationMapEntry(500, 10, 60, 0),
            new LocationMapEntry(600, 10, 150, 0),
        ];

        IReadOnlyList<LocationMapEntry> rebased =
            ContentChunkSplitter.RebaseLocationMap(map, textWindowStart: 50, textWindowLength: 100);

        LocationMapEntry entry = Assert.Single(rebased);
        Assert.Equal(new LocationMapEntry(500, 10, 10, 0), entry);
    }

    [Fact]
    public void unsplittable_chunk_returns_null()
    {
        Assert.Null(ContentChunkSplitter.SplitForFrame(MakeChunk("x"), _ => int.MaxValue));
        Assert.Null(ContentChunkSplitter.SplitForFrame(
            MakeChunk("oversize but minimal"), _ => int.MaxValue));
    }

    private static IReadOnlyList<ContentChunk> SplitOrThrow(ContentChunk chunk) =>
        ContentChunkSplitter.SplitForFrame(chunk, MeasureFrameBytes)
        ?? throw new InvalidOperationException("Expected the chunk to split.");

    private static string BuildOversizeText()
    {
        var builder = new StringBuilder(EscapeDenseUnit.Length * OversizeRepeats);
        for (int i = 0; i < OversizeRepeats; i++)
            builder.Append(EscapeDenseUnit);
        return builder.ToString();
    }

    private static List<LocationMapEntry> BuildRunMap(string text)
    {
        const int runChars = 4_096;
        var map = new List<LocationMapEntry>();
        long bytePosition = 0;
        int charPosition = 0;
        while (charPosition < text.Length)
        {
            int runLength = Math.Min(runChars, text.Length - charPosition);
            if (runLength > 1
                && charPosition + runLength < text.Length
                && char.IsHighSurrogate(text[charPosition + runLength - 1]))
            {
                runLength--;
            }

            long runBytes = Encoding.UTF8.GetByteCount(
                text.Substring(charPosition, runLength));
            map.Add(new LocationMapEntry(bytePosition, runBytes, charPosition, runLength));
            bytePosition += runBytes;
            charPosition += runLength;
        }

        return map;
    }

    private static ContentChunk MakeChunk(string text, long sourceStart = 0,
        long? sourceLength = null, IReadOnlyList<LocationMapEntry>? map = null,
        bool isFinal = true) =>
        new(
            ProtocolVersion: ProtocolConstants.Version,
            JobId: TestJobId,
            Sequence: 0,
            VirtualPath: "assets/big.jsonl",
            FormatId: "text",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: text,
            SourceStart: sourceStart,
            SourceLength: sourceLength ?? Encoding.UTF8.GetByteCount(text),
            LocationMap: map ?? Array.Empty<LocationMapEntry>(),
            IsFinal: isFinal);

    private static int MeasureFrameBytes(ContentChunk chunk)
    {
        // Same double-serialization path as the worker send
        // (WorkerSessionContext.SerializeFrame).
        string payload = JsonSerializer.Serialize(
            chunk, ProtocolJsonContext.Default.ContentChunk);
        ProtocolEnvelope envelope = ProtocolEnvelope.Create(
            MessageType.ContentChunk, Guid.NewGuid(), payload, TestScanId, TestJobId);
        return JsonSerializer.SerializeToUtf8Bytes(envelope,
            ProtocolJsonContext.Default.ProtocolEnvelope).Length;
    }
}
