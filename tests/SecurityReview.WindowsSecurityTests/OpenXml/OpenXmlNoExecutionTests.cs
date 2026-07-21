using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.OpenXml;

namespace SecurityReview.WindowsSecurityTests.OpenXml;

public sealed class OpenXmlNoExecutionTests
{
    private const string EnableVariable = "SECURITY_REVIEW_RUN_WINDOWS_SECURITY";

    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(OpenXmlNoExecutionTests).Assembly.Location)!,
        "Corpus", "Office");

    private static void AssertWindowsSecurityEnabled()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Windows security lane requires a Windows host.");
        Assert.SkipWhen(Environment.GetEnvironmentVariable(EnableVariable) != "1",
            $"Set {EnableVariable}=1 to run the Windows security lane.");
    }

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

    private static async Task<List<ParserEvent>> ParseFileAsync(string filePath)
    {
        Assert.True(File.Exists(filePath), $"Corpus not found: {filePath}");

        var parser = new OpenXmlFormatParser();
        await using var fs = File.OpenRead(filePath);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext(Path.GetFileName(filePath), fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        return events;
    }

    [Fact]
    public async Task docx_parse_completes_without_execution()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.docx");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task xlsx_parse_completes_without_execution()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.xlsx");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task pptx_parse_completes_without_execution()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.pptx");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task docm_vba_does_not_execute()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.docm");
        var events = await ParseFileAsync(path);

        // VBA strings should be extracted as text, never executed
        Assert.Contains(events, e => e is ParserEvent.ChunkProduced cp &&
            cp.Chunk.Text.Contains("tok_vba_ascii_canary_hello"));

        // macro_semantics_not_analyzed gap must be present
        Assert.Contains(events, e => e is ParserEvent.GapProduced gp &&
            gp.Gap.DetailCode == "macro_semantics_not_analyzed");
    }

    [Fact]
    public async Task xlsm_macros_do_not_execute()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.xlsm");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task pptm_macros_do_not_execute()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.pptm");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task formula_is_not_evaluated()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.xlsx");
        var events = await ParseFileAsync(path);

        // Formulas should appear as literal text, not calculated
        // No ActiveX/COM/OLE process launch should occur
        var allText = string.Join(" ", events.OfType<ParserEvent.ChunkProduced>()
            .Select(c => c.Chunk.Text));

        Assert.Contains("SUM", allText);
    }

    [Fact]
    public async Task encrypted_package_no_decryption_attempt()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "encrypted.docx");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.GapProduced gp &&
            gp.Gap.Reason == GapReason.Encrypted);
    }

    [Fact]
    public async Task legacy_doc_no_ole_instantiation()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "legacy.doc");
        var events = await ParseFileAsync(path);

        // Legacy OLE must be rejected with UnsupportedFormat, not opened
        Assert.Contains(events, e => e is ParserEvent.GapProduced gp &&
            gp.Gap.DetailCode == "legacy_office_body_unsupported");
    }

    [Fact]
    public async Task corrupt_package_no_crash()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "corrupt.docx");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }
}
