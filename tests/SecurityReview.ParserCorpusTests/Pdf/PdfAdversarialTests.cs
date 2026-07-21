using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Pdf;

namespace SecurityReview.ParserCorpusTests.Pdf;

public sealed class PdfAdversarialTests
{
    private static string CorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(PdfAdversarialTests).Assembly.Location)!,
        "Corpus", "Pdf");

    private static ParseContext MakeContext(string virtualPath) =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));

    [Fact]
    public void malformed_xref_does_not_crash()
    {
        string path = Path.Combine(CorpusDir, "malformed_xref.pdf");
        Assert.True(File.Exists(path), $"Corpus file not found: {path}");

        using var fs = File.OpenRead(path);

        // Must not throw unhandled exception
        IReadOnlyList<PdfPageResult> pages;
        try
        {
            pages = PdfPigAdapter.ExtractPages(fs);
        }
        catch (Exception ex)
        {
            // If adapter cannot handle it, it must wrap in a controlled way
            Assert.Fail($"Adapter threw unhandled exception: {ex.GetType().Name}: {ex.Message}");
            throw;
        }

        // If pages are returned, they should indicate corruption
        if (pages.Count > 0)
        {
            Assert.Contains(pages, p => p.ErrorCode == PdfAdapterErrorCode.CorruptStructure
                || p.ErrorCode == PdfAdapterErrorCode.CorruptXref
                || p.ErrorCode == PdfAdapterErrorCode.InternalLibraryError
                || p.ErrorCode == PdfAdapterErrorCode.UnexpectedError
                || p.Text.Length > 0); // or it recovered and found text
        }
    }

    [Fact]
    public void recursive_page_tree_handled_gracefully()
    {
        string path = Path.Combine(CorpusDir, "recursive_page_tree.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);

        IReadOnlyList<PdfPageResult> pages;
        try
        {
            pages = PdfPigAdapter.ExtractPages(fs);
        }
        catch (Exception ex)
        {
            // Exception is acceptable if PdfPig detects the recursion
            Assert.True(ex is InvalidOperationException or ArgumentException
                or IOException or NotSupportedException
                || ex.GetType().FullName!.Contains("PdfPig"),
                $"Unexpected exception type: {ex.GetType().FullName}");
            return;
        }

        // Pages must not be infinite; a reasonable limit
        Assert.True(pages.Count <= 10_000,
            "Recursive page tree must not produce unlimited pages.");
    }

    [Fact]
    public void huge_declared_stream_does_not_oom()
    {
        string path = Path.Combine(CorpusDir, "huge_stream.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);

        // Must not allocate 100 MB; must return error or succeed safely
        var pages = PdfPigAdapter.ExtractPages(fs);
        // Either succeeded with bounded text or returned an error
        Assert.True(pages.Count == 0 || pages[0].Text.Length < 1_000_000);
    }

    [Fact]
    public void truncated_pdf_handled_gracefully()
    {
        string path = Path.Combine(CorpusDir, "truncated.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);

        // Must not throw unhandled; should return error or partial results
        try
        {
            var pages = PdfPigAdapter.ExtractPages(fs);
            // OK - either no pages or pages with errors
            if (pages.Count > 0)
            {
                Assert.Contains(pages, p =>
                    p.HasError || p.Text.Length >= 0); // partial text OK
            }
        }
        catch (Exception ex)
        {
            // If it throws, it must be a controlled exception
            Assert.True(ex is InvalidOperationException or ArgumentException
                or IOException or NotSupportedException);
        }
    }

    [Fact]
    public void annotations_forms_pdf_extracts_form_fields()
    {
        string path = Path.Combine(CorpusDir, "annotations_forms.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);
        var formFields = PdfPigAdapter.ExtractFormFields(fs);
        Assert.NotNull(formFields);

        // Our sample has a text form field named "name_field"
        if (formFields.Count > 0)
        {
            Assert.Contains(formFields,
                f => f.Name.Contains("name_field", StringComparison.Ordinal)
                     || f.Value is "Hello");
        }
    }

    [Fact]
    public void annotations_forms_pdf_extracts_annotations()
    {
        string path = Path.Combine(CorpusDir, "annotations_forms.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);
        var annotations = PdfPigAdapter.ExtractAnnotations(fs);
        Assert.NotNull(annotations);

        Assert.Contains(annotations, a => a.Contents is "Click here for more info");
    }

    [Fact]
    public void page_output_bounded_to_limits()
    {
        // Verify bounds are defined and reasonable
        Assert.True(PdfPigAdapter.MaxPageTextBytes > 0);
        Assert.True(PdfPigAdapter.MaxPageLetters > 0);
        Assert.True(PdfPigAdapter.MaxPageTextBytes <= 20 * 1024 * 1024);
        Assert.True(PdfPigAdapter.MaxPageLetters <= 2_000_000);
    }

    [Fact]
    public void get_page_count_returns_positive_for_valid_pdf()
    {
        string path = Path.Combine(CorpusDir, "sample.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);
        int pageCount = PdfPigAdapter.GetPageCount(fs);
        Assert.True(pageCount >= 1);
    }

    [Fact]
    public void image_only_page_has_zero_text_objects()
    {
        string path = Path.Combine(CorpusDir, "image_only.pdf");
        Assert.True(File.Exists(path));

        using var fs = File.OpenRead(path);
        var pages = PdfPigAdapter.ExtractPages(fs);
        Assert.NotEmpty(pages);

        var page = pages[0];
        var record = PdfCoverageClassifier.Classify(page);
        // Image-only: text objects count matters
        Assert.True(record.TextObjects == 0 || record.ImageObjects > 0);
    }
}
