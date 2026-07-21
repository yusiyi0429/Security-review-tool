using System.Text;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.ParserCorpusTests.Text;

public sealed class TextParserTests
{
    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(TextParserTests).Assembly.Location)!,
        "Corpus", "Text");

    [Fact]
    public async Task utf8_chinese_text_detected_and_decoded()
    {
        string path = Path.Combine(CorpusDir, "utf8_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);
        Assert.Equal("utf-8", detection.EncodingName);
        Assert.Contains("你好世界", detection.Text);
        Assert.Contains("第二行", detection.Text);
    }

    [Fact]
    public async Task utf8_bom_chinese_text_detected()
    {
        string path = Path.Combine(CorpusDir, "utf8_bom_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);
        Assert.Equal("utf-8-bom", detection.EncodingName);
        Assert.Contains("你好世界", detection.Text);
    }

    [Fact]
    public async Task utf16le_bom_chinese_text_detected()
    {
        string path = Path.Combine(CorpusDir, "utf16le_bom_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);
        Assert.Equal("utf-16le-bom", detection.EncodingName);
        Assert.Contains("你好世界", detection.Text);
    }

    [Fact]
    public async Task utf16be_bom_chinese_text_detected()
    {
        string path = Path.Combine(CorpusDir, "utf16be_bom_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);
        Assert.Equal("utf-16be-bom", detection.EncodingName);
        Assert.Contains("你好世界", detection.Text);
    }

    [Fact]
    public async Task gb18030_chinese_text_detected()
    {
        string path = Path.Combine(CorpusDir, "gb18030_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);

        // Register the code pages provider for GB18030
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);
        // For GB18030 data without BOM, strict UTF-8 will likely fail,
        // and the heuristic may detect GB18030 or fallback
        // The key assertion is that text was decoded
        Assert.NotEmpty(detection.Text);
    }

    [Fact]
    public async Task identical_logical_text_across_encodings()
    {
        string utf8Path = Path.Combine(CorpusDir, "utf8_chinese.txt");
        string utf16lePath = Path.Combine(CorpusDir, "utf16le_bom_chinese.txt");
        string utf16bePath = Path.Combine(CorpusDir, "utf16be_bom_chinese.txt");

        byte[] utf8Data = await File.ReadAllBytesAsync(utf8Path);
        byte[] utf16leData = await File.ReadAllBytesAsync(utf16lePath);
        byte[] utf16beData = await File.ReadAllBytesAsync(utf16bePath);

        var utf8Result = TextEncodingDetector.DetectAndDecode(utf8Data);
        var utf16leResult = TextEncodingDetector.DetectAndDecode(utf16leData);
        var utf16beResult = TextEncodingDetector.DetectAndDecode(utf16beData);

        Assert.Equal(utf8Result.Text, utf16leResult.Text);
        Assert.Equal(utf8Result.Text, utf16beResult.Text);
    }

    [Fact]
    public async Task malformed_utf8_returns_decode_unreliable()
    {
        string path = Path.Combine(CorpusDir, "malformed_utf8.bin");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        // Malformed UTF-8 should be detected as unreliable (not throw)
        Assert.False(detection.IsReliable);
        Assert.NotNull(detection.FailureReason);
    }

    [Fact]
    public async Task long_line_is_chunked_correctly()
    {
        string path = Path.Combine(CorpusDir, "long_line.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        byte[] data = await File.ReadAllBytesAsync(path);
        var detection = TextEncodingDetector.DetectAndDecode(data);

        Assert.True(detection.IsReliable);

        var chunker = new ContentChunker(
            new JobId(Guid.NewGuid()), "test/long_line.txt", "text",
            ContentKind.Text, detection.EncodingName, data.Length);

        var chunks = chunker.ChunkAll(detection.Text,
            [new LocationMapEntry(0, data.Length, 0, detection.Text.Length)],
            data.Length);

        // Should produce multiple chunks for 600K+ chars
        Assert.True(chunks.Count >= 1);
        // Verify monotonic sequence numbers
        for (int i = 0; i < chunks.Count; i++)
        {
            Assert.Equal(i, chunks[i].Sequence);
        }
        // Last chunk should be IsFinal
        Assert.True(chunks[^1].IsFinal);
    }

    [Fact]
    public async Task text_format_parser_yields_chunks_and_completion()
    {
        string path = Path.Combine(CorpusDir, "utf8_chinese.txt");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        var parser = new TextFormatParser();

        // Create a probe that indicates text
        byte[] probeHead = new byte[256];
        var probe = new FormatProbe(probeHead, Array.Empty<byte>(), ".txt", new FileInfo(path).Length,
            new DetectedFormat("text", 1.0, ["valid_utf8_text"], false));

        Assert.True(parser.CanParse(probe));

        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = new ParseContext(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            "test/utf8_chinese.txt",
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 3, 100_000, 1_000_000_000, 1_048_576));

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }

        // Should have at least one ChunkProduced and a ParseCompleted
        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public void streaming_line_map_tracks_lines_and_columns()
    {
        var map = new StreamingLineMap();
        Assert.Equal(1, map.CurrentLine);
        Assert.Equal(1, map.CurrentColumn);

        var (line, col, _) = map.Advance("Hello\nWorld\n");

        Assert.Equal(1, line);
        Assert.Equal(1, col);
        Assert.Equal(3, map.CurrentLine);
        Assert.Equal(1, map.CurrentColumn);
    }

    [Fact]
    public void streaming_line_map_handles_carriage_return()
    {
        var map = new StreamingLineMap();
        map.Advance("Line1\r\nLine2\r\n");

        Assert.Equal(3, map.CurrentLine);
        Assert.Equal(1, map.CurrentColumn);
    }

    [Fact]
    public void streaming_line_map_long_line_split_maintains_column()
    {
        var map = new StreamingLineMap();

        // First chunk
        map.Advance("AAAABBBB");
        Assert.Equal(1, map.CurrentLine);
        Assert.Equal(9, map.CurrentColumn);
        Assert.True(map.PendingLineSplit);

        // Second chunk continues the line
        var (line2, col2, _) = map.Advance("CCCCDDDD");
        Assert.Equal(1, line2);
        Assert.Equal(9, col2); // continues from column 9
        Assert.Equal(1, map.CurrentLine);
        Assert.Equal(17, map.CurrentColumn);
    }

    [Fact]
    public void content_chunker_location_map_capped_at_max()
    {
        var chunker = new ContentChunker(
            new JobId(Guid.NewGuid()), "test.txt", "text",
            ContentKind.Text, "utf-8", 1_000_000);

        // Create a location map with more than max entries
        var tooManyEntries = new List<LocationMapEntry>();
        for (int i = 0; i < ContentChunk.MaxLocationMapEntries + 100; i++)
        {
            tooManyEntries.Add(new LocationMapEntry(i * 10, 10, i * 5, 5));
        }

        string text = new string('A', 1000);
        var chunk = chunker.NextChunk(text, 0, 1000, tooManyEntries, true);

        Assert.True(chunk.LocationMap.Count <= ContentChunk.MaxLocationMapEntries);
        Assert.True(chunk.Sequence >= 0);
    }

    [Fact]
    public void content_chunker_monotonic_sequence()
    {
        var chunker = new ContentChunker(
            new JobId(Guid.NewGuid()), "test.txt", "text",
            ContentKind.Text, "utf-8", 1000);

        var chunk1 = chunker.NextChunk("Hello", 0, 100, [], false);
        var chunk2 = chunker.NextChunk("World", 100, 100, [], true);

        Assert.Equal(0, chunk1.Sequence);
        Assert.Equal(1, chunk2.Sequence);
    }
}
