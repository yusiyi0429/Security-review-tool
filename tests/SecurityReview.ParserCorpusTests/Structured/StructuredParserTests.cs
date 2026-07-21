using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Structured;

namespace SecurityReview.ParserCorpusTests.Structured;

public sealed class StructuredParserTests
{
    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(StructuredParserTests).Assembly.Location)!,
        "Corpus", "Structured");

    private static ParseContext CreateContext(string virtualPath, long sourceLength) =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 3, 100_000, 100_000_000, 1_048_576));

    private static FormatProbe CreateProbe(string formatId) =>
        new(
            Array.Empty<byte>(), Array.Empty<byte>(), null, 0,
            new DetectedFormat(formatId, 1.0, [$"test_{formatId}"], false));

    // --- JSON tests ---

    [Fact]
    public async Task json_parser_can_parse_json_format()
    {
        var parser = new JsonFormatParser();
        Assert.True(parser.CanParse(CreateProbe("json")));
    }

    [Fact]
    public async Task json_parser_yields_chunks_for_valid_json()
    {
        string path = Path.Combine(CorpusDir, "json", "valid_simple.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_simple.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task json_parser_handles_nested_structure()
    {
        string path = Path.Combine(CorpusDir, "json", "valid_nested.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_nested.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        Assert.Equal(ContentKind.StructuredData, chunk.Chunk.ContentKind);
        // The text output should contain the token value
        Assert.Contains("tok_alice_123", chunk.Chunk.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task json_parser_rejects_duplicate_keys()
    {
        string path = Path.Combine(CorpusDir, "json", "adversarial_duplicate_keys.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/duplicate_keys.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode == "json_duplicate_property");
    }

    [Fact]
    public async Task json_parser_handles_corrupt_json()
    {
        string path = Path.Combine(CorpusDir, "json", "adversarial_unclosed_string.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/unclosed_string.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // Should have a corrupt gap and a completed event
        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.Reason == GapReason.Corrupt);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task json_parser_handles_trailing_comma()
    {
        string path = Path.Combine(CorpusDir, "json", "adversarial_trailing_comma.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/trailing_comma.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // Trailing comma should produce corrupt
        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.Reason == GapReason.Corrupt);
    }

    [Fact]
    public async Task json_parser_handles_empty_file()
    {
        string path = Path.Combine(CorpusDir, "json", "adversarial_empty.json");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new JsonFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/empty.json", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // Should terminate cleanly
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    // --- XML tests ---

    [Fact]
    public async Task xml_parser_can_parse_xml_format()
    {
        var parser = new XmlFormatParser();
        Assert.True(parser.CanParse(CreateProbe("xml")));
    }

    [Fact]
    public async Task xml_parser_yields_chunks_for_valid_xml()
    {
        string path = Path.Combine(CorpusDir, "xml", "valid_simple.xml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new XmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_simple.xml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task xml_parser_handles_nested_structure()
    {
        string path = Path.Combine(CorpusDir, "xml", "valid_nested.xml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new XmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_nested.xml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        Assert.Contains("tok_alice_123", chunk.Chunk.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task xml_parser_rejects_dtd()
    {
        string path = Path.Combine(CorpusDir, "xml", "adversarial_dtd.xml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new XmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/dtd.xml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode == "xml_dtd_prohibited");
    }

    [Fact]
    public async Task xml_parser_rejects_xxe()
    {
        string path = Path.Combine(CorpusDir, "xml", "adversarial_xxe.xml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new XmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/xxe.xml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode == "xml_dtd_prohibited");
    }

    [Fact]
    public async Task xml_parser_handles_malformed_xml()
    {
        string path = Path.Combine(CorpusDir, "xml", "adversarial_malformed.xml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new XmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/malformed.xml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.Reason == GapReason.Corrupt);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    // --- CSV tests ---

    [Fact]
    public async Task csv_parser_can_parse_csv_format()
    {
        var parser = new CsvFormatParser();
        Assert.True(parser.CanParse(CreateProbe("csv")));
    }

    [Fact]
    public async Task csv_parser_yields_chunks_for_valid_csv()
    {
        string path = Path.Combine(CorpusDir, "csv", "valid_comma.csv");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new CsvFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_comma.csv", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task csv_parser_detects_tab_delimiter()
    {
        string path = Path.Combine(CorpusDir, "csv", "valid_tab.tsv");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new CsvFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_tab.tsv", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        // Tab-separated should not produce ambiguous gap
        Assert.DoesNotContain(events, e =>
            e is ParserEvent.GapProduced g && g.Gap.DetailCode == "csv_dialect_ambiguous");
    }

    [Fact]
    public async Task csv_parser_handles_quoted_fields()
    {
        string path = Path.Combine(CorpusDir, "csv", "valid_quoted.csv");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new CsvFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_quoted.csv", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        // Quoted fields should contain the content with commas
        Assert.Contains("hello, world", chunk.Chunk.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task csv_parser_handles_no_header()
    {
        string path = Path.Combine(CorpusDir, "csv", "valid_no_header.csv");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new CsvFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_no_header.csv", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task csv_parser_handles_crlf()
    {
        string path = Path.Combine(CorpusDir, "csv", "valid_crlf.csv");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new CsvFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_crlf.csv", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
    }

    // --- YAML tests ---

    [Fact]
    public async Task yaml_parser_can_parse_yaml_format()
    {
        var parser = new YamlFormatParser();
        Assert.True(parser.CanParse(CreateProbe("yaml")));
    }

    [Fact]
    public async Task yaml_parser_yields_chunks_for_valid_yaml()
    {
        string path = Path.Combine(CorpusDir, "yaml", "valid_simple.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_simple.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task yaml_parser_handles_nested_structure()
    {
        string path = Path.Combine(CorpusDir, "yaml", "valid_nested.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/valid_nested.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        Assert.Contains("tok_alice_123", chunk.Chunk.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task yaml_parser_rejects_custom_tags()
    {
        string path = Path.Combine(CorpusDir, "yaml", "adversarial_custom_tag.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/custom_tag.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode == "yaml_custom_tag_unsupported");
    }

    [Fact]
    public async Task yaml_parser_handles_deep_nesting()
    {
        string path = Path.Combine(CorpusDir, "yaml", "adversarial_deep.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/deep.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode == "yaml_depth_limit");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task yaml_parser_handles_anchors_and_aliases()
    {
        string path = Path.Combine(CorpusDir, "yaml", "valid_anchors.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/anchors.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task yaml_parser_handles_empty_file()
    {
        string path = Path.Combine(CorpusDir, "yaml", "adversarial_empty.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/empty.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task yaml_parser_handles_sequence()
    {
        string path = Path.Combine(CorpusDir, "yaml", "valid_sequence.yaml");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new YamlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("test/sequence.yaml", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        var chunk = events.OfType<ParserEvent.ChunkProduced>().FirstOrDefault();
        Assert.NotNull(chunk);
        Assert.Contains("red", chunk.Chunk.Text, StringComparison.Ordinal);
        Assert.Contains("green", chunk.Chunk.Text, StringComparison.Ordinal);
        Assert.Contains("blue", chunk.Chunk.Text, StringComparison.Ordinal);
    }
}
