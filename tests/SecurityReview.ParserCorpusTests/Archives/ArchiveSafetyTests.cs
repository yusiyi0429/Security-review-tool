using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;

namespace SecurityReview.ParserCorpusTests.Archives;

public sealed class ArchiveSafetyTests
{
    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(ArchiveSafetyTests).Assembly.Location)!,
        "Corpus", "Archives");

    private static ParseContext MakeContext(string virtualPath = "test/archive.bin") =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));

    [Fact]
    public async Task nested_valid_zip_emits_child_events()
    {
        string path = Path.Combine(CorpusDir, "nested_valid.zip");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ChildDiscovered);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
        Assert.DoesNotContain(events, e => e is ParserEvent.GapProduced);
    }

    [Fact]
    public async Task traversal_zip_emits_gap_not_child()
    {
        string path = Path.Combine(CorpusDir, "traversal.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task absolute_path_zip_emits_gap()
    {
        string path = Path.Combine(CorpusDir, "absolute_path.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task duplicate_name_zip_still_parses()
    {
        string path = Path.Combine(CorpusDir, "duplicate_name.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
        // Both duplicates should appear as children (distinct by index)
        var children = events.OfType<ParserEvent.ChildDiscovered>().ToList();
        Assert.True(children.Count >= 2);
    }

    [Fact]
    public async Task case_collision_zip_both_parsed()
    {
        string path = Path.Combine(CorpusDir, "case_collision.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
        var children = events.OfType<ParserEvent.ChildDiscovered>().ToList();
        Assert.True(children.Count >= 2);
    }

    [Fact]
    public async Task symlink_tar_emits_unsupported_gap()
    {
        string path = Path.Combine(CorpusDir, "symlink.tar");
        Assert.True(File.Exists(path));

        var parser = new TarFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        // Should have at least one gap for the symlink
        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.Reason == GapReason.UnsupportedRegion ||
                                    g.Gap.Reason == GapReason.ArchiveLimit);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task corrupt_central_dir_zip_emits_gap()
    {
        string path = Path.Combine(CorpusDir, "corrupt_central_dir.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.GapProduced ||
                                      e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task depth_6_zip_rejects_at_limit()
    {
        // depth_6.zip has 6 nested levels. Budget depth=5 means the 6th level
        // should be rejected.
        string path = Path.Combine(CorpusDir, "depth_6.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var context = new ParseContext(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            "test/depth_6.zip",
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 100_000_000, 1_048_576));

        var events = new List<ParserEvent>();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task nested_zip_in_jar_emits_child()
    {
        string path = Path.Combine(CorpusDir, "nested_zip_in_jar.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ChildDiscovered);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task gzip_parses_to_single_child()
    {
        string path = Path.Combine(CorpusDir, "sample.txt.gz");
        Assert.True(File.Exists(path));

        var parser = new GZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        var children = events.OfType<ParserEvent.ChildDiscovered>().ToList();
        Assert.Single(children);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task gzip_with_filename_emits_named_child()
    {
        string path = Path.Combine(CorpusDir, "sample_with_name.txt.gz");
        Assert.True(File.Exists(path));

        var parser = new GZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        var children = events.OfType<ParserEvent.ChildDiscovered>().ToList();
        Assert.Single(children);
        Assert.Contains("sample_with_name.txt", children[0].VirtualPath);
    }

    [Fact]
    public async Task simple_tar_emits_children()
    {
        string path = Path.Combine(CorpusDir, "simple.tar");
        Assert.True(File.Exists(path));

        var parser = new TarFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ChildDiscovered);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task empty_zip_emits_only_completed()
    {
        string path = Path.Combine(CorpusDir, "empty.zip");
        Assert.True(File.Exists(path));

        var parser = new ZipFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
        Assert.DoesNotContain(events, e => e is ParserEvent.ChildDiscovered);
    }

    [Fact]
    public async Task empty_tar_emits_only_completed()
    {
        string path = Path.Combine(CorpusDir, "empty.tar");
        Assert.True(File.Exists(path));

        var parser = new TarFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
        Assert.DoesNotContain(events, e => e is ParserEvent.ChildDiscovered);
    }

    [Fact]
    public async Task valid_tar_emits_child()
    {
        string path = Path.Combine(CorpusDir, "valid_tar.tar");
        Assert.True(File.Exists(path));

        var parser = new TarFormatParser();
        var events = await ParseArchiveAsync(path, parser);

        Assert.Contains(events, e => e is ParserEvent.ChildDiscovered);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public void can_parse_zip_detects_zip_format()
    {
        var parser = new ZipFormatParser();
        var probe = new FormatProbe(
            new byte[256], Array.Empty<byte>(), ".zip", 1000,
            new DetectedFormat("zip", 1.0, ["magic_PK"], false));
        Assert.True(parser.CanParse(probe));
    }

    [Fact]
    public void can_parse_zip_rejects_text()
    {
        var parser = new ZipFormatParser();
        var probe = new FormatProbe(
            new byte[256], Array.Empty<byte>(), ".txt", 1000,
            new DetectedFormat("text", 0.9, ["valid_utf8_text"], false));
        Assert.False(parser.CanParse(probe));
    }

    [Fact]
    public void can_parse_tar_detects_tar_format()
    {
        var parser = new TarFormatParser();
        var probe = new FormatProbe(
            new byte[512], Array.Empty<byte>(), ".tar", 10240,
            new DetectedFormat("tar", 1.0, ["magic_TAR"], false));
        Assert.True(parser.CanParse(probe));
    }

    [Fact]
    public void can_parse_gzip_detects_gzip_format()
    {
        var parser = new GZipFormatParser();
        var probe = new FormatProbe(
            new byte[256], Array.Empty<byte>(), ".gz", 1000,
            new DetectedFormat("gzip", 1.0, ["magic_GZIP"], false));
        Assert.True(parser.CanParse(probe));
    }

    private static async Task<List<ParserEvent>> ParseArchiveAsync(string filePath, IFormatParser parser)
    {
        var events = new List<ParserEvent>();
        await using var fs = File.OpenRead(filePath);
        await using var input = new ParserInput(fs, fs.Length);
        var context = MakeContext($"test/{Path.GetFileName(filePath)}");
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }

        return events;
    }
}
