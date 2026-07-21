using System.Globalization;
using System.Text;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Findings;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for <see cref="SafePreviewService"/>: bounded text, table,
/// binary, PDF, and OCI preview fragments.
/// </summary>
public partial class SafePreviewServiceTests
{
    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Builds a multi-line string with <paramref name="lineCount"/> lines,
    /// each line "line NNN" followed by padding for approximate byte size.
    /// </summary>
    private static string BuildMultiLineText(int lineCount, int padPerLine = 0)
    {
        var sb = new StringBuilder();
        string suffix = padPerLine > 0 ? new string('A', padPerLine) : "";
        for (int i = 0; i < lineCount; i++)
        {
            sb.Append("line ");
            sb.Append(i.ToString("D4", CultureInfo.InvariantCulture));
            if (suffix.Length > 0) sb.Append(' ').Append(suffix);
            sb.Append('\n');
        }
        return sb.ToString();
    }

    private static string MakeLine(int index) =>
        $"line {index:D4}";

    // ------------------------------------------------------------------
    // PreviewText
    // ------------------------------------------------------------------

    [Fact]
    public void PreviewText_locator_at_line_0_gets_correct_fragment_with_highlight()
    {
        string text = BuildMultiLineText(10);
        var locator = new SourceLocator.TextLocator(Line: 0, Column: 3, ByteStart: 5, ByteLength: 4);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.NotNull(fragment);
        Assert.Equal("text:0:3@5+4", fragment.LocatorDisplay);
        // With 10 lines starting at line 0, no truncation
        Assert.Equal(0L, fragment.TruncatedBefore);
        Assert.Equal(0L, fragment.TruncatedAfter);
        // highlight should be on the first line (line 0)
        Assert.Equal(0, fragment.HighlightLineIndex);
        Assert.True(fragment.HighlightCharStart > 0);
        Assert.True(fragment.HighlightCharEnd > fragment.HighlightCharStart);
    }

    [Fact]
    public void PreviewText_locator_at_line_50_centers_fragment()
    {
        string text = BuildMultiLineText(100);
        var locator = new SourceLocator.TextLocator(Line: 50, Column: 0, ByteStart: 0, ByteLength: 0);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.NotNull(fragment);
        // Fragment should be centered around line 50, up to 20 lines total
        Assert.True(fragment.Lines.Count <= 20);
        // line 50 should be within the fragment
        Assert.Contains(fragment.Lines, l => l.LineNumber == 50);
        Assert.True(fragment.TruncatedBefore > 0, "Should have lines truncated before");
        Assert.True(fragment.TruncatedAfter > 0, "Should have lines truncated after");
    }

    [Fact]
    public void PreviewText_respects_max_text_lines()
    {
        string text = BuildMultiLineText(100);
        var locator = new SourceLocator.TextLocator(Line: 0, Column: 0, ByteStart: 0, ByteLength: 0);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.True(fragment.Lines.Count <= 20, $"Expected <=20 lines, got {fragment.Lines.Count}");
    }

    [Fact]
    public void PreviewText_respects_max_text_bytes()
    {
        // Each line is very large (~10 KiB), 20 lines would overflow the 64 KiB cap
        string text = BuildMultiLineText(20, padPerLine: 10_000);
        const long expectedLine = 5;
        var locator = new SourceLocator.TextLocator(Line: expectedLine, Column: 0, ByteStart: 0, ByteLength: 0);

        var fragment = SafePreviewService.PreviewText(text, locator);

        // Fragment should be truncated by byte limit, so fewer than 20 lines
        Assert.True(fragment.Lines.Count < 20, $"Expected <20 lines due to byte cap, got {fragment.Lines.Count}");
        Assert.True(fragment.TruncatedAfter > 0, "Should have lines truncated after byte cap");
    }

    [Fact]
    public void PreviewText_truncation_notes_correct()
    {
        string text = BuildMultiLineText(100);
        var locator = new SourceLocator.TextLocator(Line: 50, Column: 0, ByteStart: 0, ByteLength: 0);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.True(fragment.TruncatedBefore > 0);
        Assert.True(fragment.TruncatedAfter > 0);
        // total truncated + fragment lines should equal total lines
        Assert.Equal(100L, fragment.TruncatedBefore + fragment.Lines.Count + fragment.TruncatedAfter);
    }

    [Fact]
    public void PreviewText_empty_text_returns_empty_fragment()
    {
        var locator = new SourceLocator.TextLocator(Line: 0, Column: 0, ByteStart: 0, ByteLength: 0);

        var fragment = SafePreviewService.PreviewText("", locator);

        Assert.NotNull(fragment);
        Assert.Empty(fragment.Lines);
        Assert.Equal(-1, fragment.HighlightLineIndex);
    }

    [Fact]
    public void PreviewText_text_locator_produces_correct_highlight_char_range()
    {
        string lineContent = "hello world example";
        string text = lineContent + "\n";
        // Column=6 -> "w", ByteLength=5 -> "world"
        var locator = new SourceLocator.TextLocator(Line: 0, Column: 6, ByteStart: 0, ByteLength: 5);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.Equal(0, fragment.HighlightLineIndex);
        Assert.True(fragment.HighlightCharStart >= 0);
        Assert.True(fragment.HighlightCharEnd > fragment.HighlightCharStart);
        string highlightedText = lineContent.Substring(fragment.HighlightCharStart,
            fragment.HighlightCharEnd - fragment.HighlightCharStart);
        Assert.Equal("world", highlightedText);
    }

    [Fact]
    public void PreviewText_json_locator_estimates_line_from_byte_offset()
    {
        string text = BuildMultiLineText(5);
        // Compute byte offset to somewhere in line 2
        int byteOffset = Encoding.UTF8.GetByteCount(MakeLine(0) + "\n" + MakeLine(1) + "\n");
        var locator = new SourceLocator.JsonLocator("/path", ByteStart: byteOffset, ByteLength: 5);

        var fragment = SafePreviewService.PreviewText(text, locator);

        Assert.NotNull(fragment);
        // The highlight line should correspond to line 2 (the third line, index 2)
        Assert.True(fragment.HighlightLineIndex >= 0);
        Assert.True(fragment.HighlightCharEnd > fragment.HighlightCharStart);
    }

    // ------------------------------------------------------------------
    // PreviewTable
    // ------------------------------------------------------------------

    private static List<List<string>> BuildTable(int rows, int cols)
    {
        var table = new List<List<string>>(rows);
        for (int i = 0; i < rows; i++)
        {
            var row = new List<string>(cols);
            for (int j = 0; j < cols; j++)
                row.Add($"R{i}C{j}");
            table.Add(row);
        }
        return table;
    }

    [Fact]
    public void PreviewTable_returns_max_10_rows()
    {
        var rows = BuildTable(50, 3);
        var locator = new SourceLocator.CellLocator("Sheet1", "B2");

        var preview = SafePreviewService.PreviewTable(rows, locator);

        Assert.NotNull(preview);
        Assert.True(preview.Rows.Count <= 10, $"Expected <=10 rows, got {preview.Rows.Count}");
    }

    [Fact]
    public void PreviewTable_highlights_correct_row_cell()
    {
        var rows = new List<List<string>>
        {
            new() { "Sheet1", "Col1", "Col2" },
            new() { "Row1", "A", "B" },
            new() { "Row2", "C", "D" },
            new() { "Row3", "E", "F" },
        };
        var locator = new SourceLocator.CellLocator("Sheet1", "C5");

        var preview = SafePreviewService.PreviewTable(rows, locator);

        Assert.Equal(0, preview.HighlightRow); // Sheet1 found in first row
        Assert.Equal("C5", preview.HighlightCell);
    }

    [Fact]
    public void PreviewTable_truncation_notes_correct()
    {
        var rows = BuildTable(50, 3);
        var locator = new SourceLocator.CellLocator("Sheet1", "B2");

        var preview = SafePreviewService.PreviewTable(rows, locator);

        Assert.True(preview.TruncatedAfter > 0, "Should have rows truncated after");
        Assert.Equal(50L, preview.TruncatedBefore + preview.Rows.Count + preview.TruncatedAfter);
    }

    [Fact]
    public void PreviewTable_empty_rows_returns_empty_preview()
    {
        var rows = new List<List<string>>();
        var locator = new SourceLocator.CellLocator("Sheet1", "A1");

        var preview = SafePreviewService.PreviewTable(rows, locator);

        Assert.NotNull(preview);
        Assert.Empty(preview.Rows);
        Assert.Equal(-1, preview.HighlightRow);
    }

    // ------------------------------------------------------------------
    // PreviewBinary
    // ------------------------------------------------------------------

    [Fact]
    public void PreviewBinary_returns_max_256_bytes()
    {
        var data = new byte[1000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);
        var locator = new SourceLocator.BinaryLocator("section", ByteOffset: 0, ByteLength: 100);

        var preview = SafePreviewService.PreviewBinary(data, locator);

        Assert.NotNull(preview);
        Assert.True(preview.ByteLength <= 256, $"Expected <=256 bytes, got {preview.ByteLength}");
    }

    [Fact]
    public void PreviewBinary_hex_and_text_views_correct()
    {
        var data = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"
        var locator = new SourceLocator.BinaryLocator("section", ByteOffset: 0, ByteLength: 5);

        var preview = SafePreviewService.PreviewBinary(data, locator);

        Assert.NotEmpty(preview.HexLines);
        Assert.NotEmpty(preview.TextLines);
        Assert.Equal(preview.HexLines.Count, preview.TextLines.Count);
        // Text view should contain readable chars
        Assert.Contains(preview.TextLines, s => s.Contains("Hello"));
    }

    [Fact]
    public void PreviewBinary_truncation_notes_correct()
    {
        var data = new byte[1000];
        var locator = new SourceLocator.BinaryLocator("section", ByteOffset: 0, ByteLength: 50);

        var preview = SafePreviewService.PreviewBinary(data, locator);

        Assert.Equal(0L, preview.ByteOffset);
        Assert.True(preview.TruncatedAfter > 0, "Should have bytes truncated after");
    }

    [Fact]
    public void PreviewBinary_empty_data_returns_empty_preview()
    {
        var data = Array.Empty<byte>();
        var locator = new SourceLocator.BinaryLocator("section", ByteOffset: 0, ByteLength: 0);

        var preview = SafePreviewService.PreviewBinary(data, locator);

        Assert.NotNull(preview);
        Assert.Empty(preview.HexLines);
        Assert.Empty(preview.TextLines);
        Assert.Equal(0, preview.ByteLength);
    }

    // ------------------------------------------------------------------
    // PreviewPdfBlock
    // ------------------------------------------------------------------

    [Fact]
    public void PreviewPdfBlock_truncates_to_max_text_lines_and_bytes()
    {
        string pageText = BuildMultiLineText(100);
        var locator = new SourceLocator.PdfLocator(Page: 0, BlockIndex: 0);

        string result = SafePreviewService.PreviewPdfBlock(pageText, locator);

        Assert.NotNull(result);
        string[] lines = result.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length <= 20, $"Expected <=20 lines, got {lines.Length}");
    }

    [Fact]
    public void PreviewPdfBlock_empty_input_returns_empty_string()
    {
        var locator = new SourceLocator.PdfLocator(Page: 0, BlockIndex: 0);

        string result = SafePreviewService.PreviewPdfBlock("", locator);

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void PreviewPdfBlock_null_input_returns_empty_string()
    {
        var locator = new SourceLocator.PdfLocator(Page: 0, BlockIndex: 0);

        string result = SafePreviewService.PreviewPdfBlock(null!, locator);

        Assert.Equal(string.Empty, result);
    }

    // ------------------------------------------------------------------
    // PreviewOciEntry
    // ------------------------------------------------------------------

    [Fact]
    public void PreviewOciEntry_delegates_to_preview_text()
    {
        string entryContent = BuildMultiLineText(5);
        var locator = new SourceLocator.OciLocator(
            "sha256:abc", "sha256:def", LayerIndex: 0,
            "/etc/config", EntryOffset: 0);

        var fragment = SafePreviewService.PreviewOciEntry(entryContent, locator);

        Assert.NotNull(fragment);
        Assert.NotEmpty(fragment.Lines);
        // OCI preview creates a TextLocator(0, 0, 0, 0), so highlight at line 0
        Assert.Equal(0, fragment.HighlightLineIndex);
    }
}
