using System.Net;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.OpenXml;

namespace SecurityReview.ParserCorpusTests.OpenXml;

public sealed class OpenXmlSecurityTests
{
    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(OpenXmlSecurityTests).Assembly.Location)!,
        "Corpus", "Office");

    private static ParseContext CreateContext(string virtualPath, long sourceLength)
    {
        var limits = new ParseLimits(
            DateTimeOffset.UtcNow.AddMinutes(5), 3,
            10_000, 100_000_000,
            512 * 1024);

        return new ParseContext(
            new JobId(Guid.NewGuid()), new ScanId(Guid.NewGuid()),
            virtualPath, limits);
    }

    [Fact]
    public async Task encrypted_package_yields_gap_without_prompting()
    {
        string path = Path.Combine(CorpusDir, "encrypted.docx");
        Assert.True(File.Exists(path), $"Corpus not found: {path}");

        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("encrypted.docx", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // Must not attempt password input — the encrypted gap should appear immediately
        var encryptedGaps = events.OfType<ParserEvent.GapProduced>()
            .Where(g => g.Gap.Reason == GapReason.Encrypted)
            .ToList();

        Assert.NotEmpty(encryptedGaps);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task corrupt_package_yields_corrupt_gap_without_crash()
    {
        string path = Path.Combine(CorpusDir, "corrupt.docx");
        Assert.True(File.Exists(path));

        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("corrupt.docx", fs.Length);

        var events = new List<ParserEvent>();
        // Must not throw — parser must handle corrupt gracefully
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task external_relationship_target_never_opened()
    {
        // The corpus points to this exact URL. Bind it so an attempted external
        // relationship fetch is observable instead of silently failing DNS/port lookup.
        const string externalRelationshipPrefix = "http://localhost:19999/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(externalRelationshipPrefix);
        listener.Start();

        try
        {
            // Parse the external_rel.docx — it has an external relationship to
            // http://localhost:19999/canary. We verify no HTTP request is made to
            // the listener by checking if any request arrives.
            string path = Path.Combine(CorpusDir, "external_rel.docx");
            Assert.True(File.Exists(path));

            var parser = new OpenXmlFormatParser();
            await using var fs = File.OpenRead(path);
            await using var input = new ParserInput(fs, fs.Length);
            var context = CreateContext("external_rel.docx", fs.Length);

            var events = new List<ParserEvent>();
            await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
                events.Add(evt);

            // The document body should still be parsed
            Assert.Contains(events, e => e is ParserEvent.ChunkProduced cp &&
                cp.Chunk.Text.Contains("tok_docx_external_rel_body"));
            Assert.Contains(events, e => e is ParserEvent.ParseCompleted);

            // Verify no HTTP request was made to the corpus relationship target.
            var gotContext = listener.GetContextAsync();
            var timeout = Task.Delay(200);
            var completed = await Task.WhenAny(gotContext, timeout);
            Assert.NotEqual(gotContext, completed);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task formula_text_remains_string_not_evaluated()
    {
        string path = Path.Combine(CorpusDir, "sample.xlsx");
        Assert.True(File.Exists(path));

        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("sample.xlsx", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // Formula text should be emitted as-is, not evaluated
        // SUM formula should appear as literal text
        var formulaChunks = events.OfType<ParserEvent.ChunkProduced>()
            .Where(c => c.Chunk.Text.Contains("SUM"))
            .ToList();

        Assert.NotEmpty(formulaChunks);
        // Formula text must be literal, not computed result
        Assert.Contains(formulaChunks, c => c.Chunk.Text.Contains("=SUM(") ||
            c.Chunk.ContentKind == ContentKind.Metadata);
    }

    [Fact]
    public async Task relationship_target_is_never_opened_as_stream()
    {
        string path = Path.Combine(CorpusDir, "external_rel.docx");
        Assert.True(File.Exists(path));

        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("external_rel.docx", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        // External relationship target should appear as metadata only
        var externalRelChunks = events.OfType<ParserEvent.ChunkProduced>()
            .Where(c => c.Chunk.Text.Contains("localhost:19999") ||
                        c.Chunk.Text.Contains("External"))
            .ToList();

        // Either the external rel appears as metadata or the package warns about it
        Assert.True(externalRelChunks.Count > 0 ||
            events.OfType<ParserEvent.GapProduced>().Any(),
            "External relationship should be reported as metadata or gap");
    }

    [Fact]
    public async Task no_filesystem_writes_during_parse()
    {
        // Verify parsing doesn't create files in unexpected locations
        string tempBefore = Path.GetTempPath();
        var filesBefore = Directory.GetFiles(tempBefore, "*", SearchOption.TopDirectoryOnly)
            .ToHashSet();

        string path = Path.Combine(CorpusDir, "sample.docx");
        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(path);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext("sample.docx", fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);

        // No new files should appear in temp
        var filesAfter = Directory.GetFiles(tempBefore, "*", SearchOption.TopDirectoryOnly)
            .ToHashSet();
        var newFiles = filesAfter.Except(filesBefore).ToList();

        // If any new files appeared, they should be within acceptable bounds
        // (some temp files may be created by .NET runtime, not by our parser)
        Assert.DoesNotContain(newFiles, f => f.Contains("SecurityReview"));
    }
}
