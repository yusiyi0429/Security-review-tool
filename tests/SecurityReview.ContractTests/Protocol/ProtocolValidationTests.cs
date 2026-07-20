using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.ContractTests.Protocol;

public sealed class ProtocolValidationTests
{
    private static readonly DateTimeOffset NowUtc = new(2026, 7, 20, 0, 0, 0, TimeSpan.Zero);

    private static ParseLimits ValidLimits() =>
        new(NowUtc.AddMinutes(5), 3, 1_000, 1_000_000, 65_536);

    [Fact]
    public void Valid_limits_pass_validation() => Assert.Empty(ValidLimits().Validate(NowUtc));

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void Deadline_not_in_the_future_is_rejected(long secondsFromNow)
    {
        var limits = ValidLimits() with { DeadlineUtc = NowUtc.AddSeconds(secondsFromNow) };
        Assert.Contains("deadline_expired", limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(6)]
    [InlineData(int.MaxValue)]
    public void Depth_outside_zero_to_five_is_rejected(int depth)
    {
        var limits = ValidLimits() with { MaxDepth = depth };
        Assert.Contains("depth_out_of_range", limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void Depth_at_bounds_is_accepted(int depth)
    {
        var limits = ValidLimits() with { MaxDepth = depth };
        Assert.Empty(limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(100_001)]
    public void Entries_outside_zero_to_one_hundred_thousand_is_rejected(int entries)
    {
        var limits = ValidLimits() with { MaxEntriesRemaining = entries };
        Assert.Contains("entries_out_of_range", limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(-1L)]
    [InlineData(53_687_091_201L)]
    public void Expanded_bytes_outside_zero_to_fifty_gib_is_rejected(long expandedBytes)
    {
        var limits = ValidLimits() with { MaxExpandedBytesRemaining = expandedBytes };
        Assert.Contains("expanded_bytes_out_of_range", limits.Validate(NowUtc));
    }

    [Fact]
    public void Expanded_bytes_at_fifty_gib_is_accepted()
    {
        var limits = ValidLimits() with { MaxExpandedBytesRemaining = 53_687_091_200L };
        Assert.Empty(limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1_048_577)]
    public void Chunk_bytes_outside_one_to_one_mebibyte_is_rejected(int chunkBytes)
    {
        var limits = ValidLimits() with { MaxChunkBytes = chunkBytes };
        Assert.Contains("chunk_bytes_out_of_range", limits.Validate(NowUtc));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1_048_576)]
    public void Chunk_bytes_at_bounds_is_accepted(int chunkBytes)
    {
        var limits = ValidLimits() with { MaxChunkBytes = chunkBytes };
        Assert.Empty(limits.Validate(NowUtc));
    }

    private static ContentChunk CreateChunk(
        long sequence = 0,
        string? virtualPath = null,
        long sourceStart = 0,
        long sourceLength = 100,
        string? text = null,
        IReadOnlyList<LocationMapEntry>? locationMap = null) =>
        new(ProtocolConstants.Version, new JobId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
            sequence, virtualPath ?? "dir/sub/file.txt", "plain-text", ContentKind.Text, "utf-8",
            text ?? new string('a', 100), sourceStart, sourceLength, locationMap ?? [], false);

    [Fact]
    public void Valid_chunk_passes_validation()
    {
        var chunk = CreateChunk(locationMap: [new LocationMapEntry(0, 50, 0, 50), new LocationMapEntry(50, 50, 50, 50)]);
        Assert.Empty(chunk.Validate(1024));
    }

    [Fact]
    public void Negative_sequence_is_rejected()
    {
        var chunk = CreateChunk(sequence: -1);
        Assert.Contains("sequence_negative", chunk.Validate(1024));
    }

    [Theory]
    [InlineData(-1L, 100L)]
    [InlineData(0L, -1L)]
    public void Negative_source_ranges_are_rejected(long sourceStart, long sourceLength)
    {
        var chunk = CreateChunk(sourceStart: sourceStart, sourceLength: sourceLength);
        Assert.Contains("source_range_invalid", chunk.Validate(1024));
    }

    [Fact]
    public void Source_range_beyond_declared_length_is_rejected()
    {
        var chunk = CreateChunk(sourceStart: 1000, sourceLength: 25);
        Assert.Contains("source_range_exceeds_declared", chunk.Validate(1024));
    }

    [Fact]
    public void Source_range_addition_overflow_is_rejected_without_throwing()
    {
        var chunk = CreateChunk(sourceStart: long.MaxValue - 1, sourceLength: 10);
        Assert.Contains("source_range_exceeds_declared", chunk.Validate(long.MaxValue));
    }

    [Fact]
    public void Location_map_with_more_than_8192_entries_is_rejected()
    {
        var entries = Enumerable.Range(0, 8193).Select(i => new LocationMapEntry(i, 1, 0, 0)).ToArray();
        var chunk = CreateChunk(sourceStart: 0, sourceLength: 8193, locationMap: entries);
        Assert.Contains("location_map_too_large", chunk.Validate(8193));
    }

    [Fact]
    public void Location_map_with_8192_entries_is_accepted()
    {
        var entries = Enumerable.Range(0, 8192).Select(i => new LocationMapEntry(i, 1, 0, 0)).ToArray();
        var chunk = CreateChunk(sourceStart: 0, sourceLength: 8192, locationMap: entries);
        Assert.Empty(chunk.Validate(8192));
    }

    [Fact]
    public void Unsorted_location_map_is_rejected()
    {
        var chunk = CreateChunk(locationMap: [new LocationMapEntry(50, 10, 0, 0), new LocationMapEntry(10, 10, 0, 0)]);
        Assert.Contains("location_map_unsorted", chunk.Validate(1024));
    }

    [Fact]
    public void Overlapping_location_map_is_rejected()
    {
        var chunk = CreateChunk(locationMap: [new LocationMapEntry(0, 60, 0, 0), new LocationMapEntry(50, 10, 0, 0)]);
        Assert.Contains("location_map_overlapping", chunk.Validate(1024));
    }

    [Theory]
    [InlineData(-1L, 10L, 0L, 10L)]
    [InlineData(0L, -10L, 0L, 10L)]
    [InlineData(0L, 10L, -1L, 10L)]
    [InlineData(0L, 10L, 0L, -10L)]
    [InlineData(2000L, 10L, 0L, 10L)]
    [InlineData(0L, 10L, 95L, 10L)]
    [InlineData(long.MaxValue - 1, 10L, 0L, 10L)]
    public void Invalid_location_map_entries_are_rejected(long sourceStart, long sourceLength, long textStart, long textLength)
    {
        var chunk = CreateChunk(locationMap: [new LocationMapEntry(sourceStart, sourceLength, textStart, textLength)]);
        Assert.Contains("location_entry_invalid", chunk.Validate(1024));
    }

    [Fact]
    public void Empty_virtual_path_is_rejected()
    {
        var chunk = CreateChunk(virtualPath: "");
        Assert.Contains("virtual_path_empty", chunk.Validate(1024));
    }

    [Fact]
    public void Virtual_path_longer_than_4096_utf16_units_is_rejected()
    {
        var chunk = CreateChunk(virtualPath: new string('目', 4097));
        Assert.Contains("virtual_path_too_long", chunk.Validate(1024));
    }

    [Fact]
    public void Virtual_path_of_4096_utf16_units_is_accepted()
    {
        var chunk = CreateChunk(virtualPath: new string('目', 4096));
        Assert.Empty(chunk.Validate(1024));
    }

    [Theory]
    [InlineData("C:\\dir\\file.txt")]
    [InlineData("z:file.txt")]
    [InlineData("/abs/path")]
    [InlineData("\\abs\\path")]
    public void Absolute_virtual_paths_are_rejected(string virtualPath)
    {
        var chunk = CreateChunk(virtualPath: virtualPath);
        Assert.Contains("virtual_path_absolute", chunk.Validate(1024));
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/../b")]
    [InlineData("a/..")]
    [InlineData("..\\file.txt")]
    public void Virtual_paths_with_parent_segments_are_rejected(string virtualPath)
    {
        var chunk = CreateChunk(virtualPath: virtualPath);
        Assert.Contains("virtual_path_parent_reference", chunk.Validate(1024));
    }

    [Fact]
    public void Virtual_path_with_nul_is_rejected()
    {
        var chunk = CreateChunk(virtualPath: "dir\0file.txt");
        Assert.Contains("virtual_path_nul", chunk.Validate(1024));
    }

    [Fact]
    public void Virtual_path_with_unpaired_surrogates_is_rejected()
    {
        string[] malformed =
        [
            "dir" + (char)0xD800 + "file.txt",
            "dir" + (char)0xDFFF + " file.txt",
            ((char)0xDFFF).ToString(),
            "dir" + (char)0xD800 + (char)0xD800 + (char)0xDC00 + "file.txt",
        ];
        foreach (string virtualPath in malformed)
        {
            var chunk = CreateChunk(virtualPath: virtualPath);
            Assert.Contains("virtual_path_malformed_unicode", chunk.Validate(1024));
        }
    }

    [Theory]
    [InlineData("目录/子目录/文件.txt")]
    [InlineData("dir\\sub\\file.txt")]
    [InlineData("a\"b'.txt")]
    [InlineData("file\tname.txt")]
    [InlineData("a.../b..c/file.")]
    public void Well_formed_relative_virtual_paths_are_accepted(string virtualPath)
    {
        var chunk = CreateChunk(virtualPath: virtualPath);
        Assert.Empty(chunk.Validate(1024));
    }

    [Fact]
    public void Worst_case_chunk_envelope_fits_one_mebibyte_frame()
    {
        const long declaredLength = 53_687_091_200L;
        var locationMap = new LocationMapEntry[8192];
        for (int i = 0; i < locationMap.Length; i++)
        {
            locationMap[i] = new LocationMapEntry(i * 6_000_000L, 5_999_999L, 0L, 0L);
        }

        var metadataOnly = new ContentChunk(
            ProtocolConstants.Version, new JobId(Guid.Parse("22222222-2222-2222-2222-222222222222")),
            8191, new string('目', 4096), "plain-text", ContentKind.Text, "utf-8",
            string.Empty, declaredLength - 5_999_999L, 5_999_999L, locationMap, true);
        Assert.Empty(metadataOnly.Validate(declaredLength));
        var metadataEnvelope = ProtocolEnvelope.Create(MessageType.ContentChunk, Guid.NewGuid(),
            JsonSerializer.Serialize(metadataOnly, ProtocolJsonContext.Default.ContentChunk),
            new ScanId(Guid.Parse("33333333-3333-3333-3333-333333333333")), metadataOnly.JobId);
        int metadataBytes = JsonSerializer.SerializeToUtf8Bytes(metadataEnvelope, ProtocolJsonContext.Default.ProtocolEnvelope).Length;

        int textBudget = ProtocolConstants.MaxFrameBytes - metadataBytes - 16;
        Assert.True(textBudget > 1_024, $"Expected positive text headroom, got {textBudget}.");
        var worstCase = metadataOnly with { Text = new string('a', textBudget) };
        var envelope = ProtocolEnvelope.Create(MessageType.ContentChunk, Guid.NewGuid(),
            JsonSerializer.Serialize(worstCase, ProtocolJsonContext.Default.ContentChunk),
            new ScanId(Guid.Parse("33333333-3333-3333-3333-333333333333")), worstCase.JobId);
        byte[] frame = JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJsonContext.Default.ProtocolEnvelope);
        Assert.True(frame.Length <= ProtocolConstants.MaxFrameBytes, $"Frame was {frame.Length} bytes.");
    }

    [Fact]
    public async Task Chunk_with_worst_case_text_round_trips_through_an_envelope()
    {
        string text = "控制字符\n中文文本 backslash \\ quote \" tab \t 目录\\文件";
        var chunk = CreateChunk(text: text, sourceLength: text.Length);
        var expected = ProtocolEnvelope.Create(MessageType.ContentChunk, Guid.NewGuid(),
            JsonSerializer.Serialize(chunk, ProtocolJsonContext.Default.ContentChunk),
            new ScanId(Guid.Parse("33333333-3333-3333-3333-333333333333")), chunk.JobId);
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, TestContext.Current.CancellationToken);
        stream.Position = 0;
        ProtocolEnvelope actual = await LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken);
        Assert.Equal(expected, actual);
        ContentChunk? roundTripped = JsonSerializer.Deserialize(actual.PayloadJson, ProtocolJsonContext.Default.ContentChunk);
        Assert.NotNull(roundTripped);
        Assert.Equal(chunk with { LocationMap = [] }, roundTripped with { LocationMap = [] });
        Assert.Equal(chunk.LocationMap.ToArray(), roundTripped.LocationMap.ToArray());
    }

    [Fact]
    public void Locators_with_maximum_metadata_stay_within_display_limit()
    {
        SourceLocator[] locators =
        [
            new SourceLocator.PathLocator(PathKind.Stream, new string('流', 4000)),
            new SourceLocator.TextLocator(long.MaxValue, long.MaxValue, 53_687_091_200L, 53_687_091_200L),
            new SourceLocator.CellLocator(new string('表', 2000), "XFD1048576"),
            new SourceLocator.JsonLocator("/" + new string('指', 2000), 53_687_091_200L, 53_687_091_200L),
            new SourceLocator.BinaryLocator(new string('段', 2000), long.MaxValue, long.MaxValue),
            new SourceLocator.PdfLocator(int.MaxValue, int.MaxValue),
            new SourceLocator.OciLocator(new string('a', 200), new string('b', 200), int.MaxValue, new string('目', 2000), long.MaxValue),
        ];
        foreach (SourceLocator locator in locators)
        {
            Assert.Empty(locator.Validate());
        }
    }

    [Fact]
    public void Locator_display_longer_than_4096_utf16_units_is_rejected()
    {
        var locator = new SourceLocator.PathLocator(PathKind.Segment, new string('x', 5000));
        Assert.Contains("locator_display_too_long", locator.Validate());
    }

    [Fact]
    public void Deeply_nested_locator_display_is_rejected_when_over_limit()
    {
        SourceLocator inner = new SourceLocator.TextLocator(1, 1, 0, 10);
        var locator = new SourceLocator.NestedLocator(new string('目', 4096), inner);
        Assert.Contains("locator_display_too_long", locator.Validate());
    }

    [Fact]
    public void Nested_locator_within_limit_is_accepted()
    {
        SourceLocator inner = new SourceLocator.CellLocator("Sheet1", "A1");
        var locator = new SourceLocator.NestedLocator("archive.zip/inner.xlsx", inner);
        Assert.Empty(locator.Validate());
        Assert.Contains("archive.zip/inner.xlsx", locator.ToCanonicalDisplay(), StringComparison.Ordinal);
    }
}
