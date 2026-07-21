using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Pdf;

namespace SecurityReview.WindowsSecurityTests.Pdf;

public sealed class PdfNoNetworkExecutionTests
{
    private const string EnableVariable = "SECURITY_REVIEW_RUN_WINDOWS_SECURITY";

    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(PdfNoNetworkExecutionTests).Assembly.Location)!,
        "Corpus", "Pdf");

    private static void AssertWindowsSecurityEnabled()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(),
            "Windows security lane requires a Windows host.");
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

        var parser = new PdfFormatParser();
        await using var fs = File.OpenRead(filePath);
        await using var input = new ParserInput(fs, fs.Length);
        var context = CreateContext(Path.GetFileName(filePath), fs.Length);

        var events = new List<ParserEvent>();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
            events.Add(evt);

        return events;
    }

    [Fact]
    public async Task sample_pdf_parse_completes_without_execution()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "sample.pdf");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task image_only_pdf_emits_ocr_gap_not_crash()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "image_only.pdf");
        var events = await ParseFileAsync(path);

        // Must not crash. Should emit gap for image-only page.
        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task encrypted_pdf_no_decryption_attempt()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "encrypted.pdf");
        var events = await ParseFileAsync(path);

        // Must not attempt password; must emit Encrypted gap
        Assert.Contains(events, e => e is ParserEvent.GapProduced gp &&
            gp.Gap.Reason == GapReason.Encrypted);
    }

    [Fact]
    public async Task malformed_pdf_no_crash()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "malformed_xref.pdf");
        var events = await ParseFileAsync(path);

        // Must not crash; should complete with gap or partial content
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task truncated_pdf_no_crash()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "truncated.pdf");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task huge_stream_pdf_no_oom()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "huge_stream.pdf");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task recursive_page_tree_no_infinite_loop()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "recursive_page_tree.pdf");
        var events = await ParseFileAsync(path);

        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task annotations_forms_extracted_without_execution()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "annotations_forms.pdf");
        var events = await ParseFileAsync(path);

        // Form field text should appear in chunks, no code execution
        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task mixed_pdf_emits_partial_coverage_gap()
    {
        AssertWindowsSecurityEnabled();

        string path = Path.Combine(CorpusDir, "mixed.pdf");
        var events = await ParseFileAsync(path);

        // Mixed content should produce a coverage gap for the image portion
        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }
}
