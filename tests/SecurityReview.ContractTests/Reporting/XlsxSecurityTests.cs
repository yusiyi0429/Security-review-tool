using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Infrastructure.Reporting;

namespace SecurityReview.ContractTests.Reporting;

/// <summary>
/// Security contract tests for <see cref="XlsxCellWriter"/> — verifies that
/// every cell written into the XLSX stream is a safe text cell with no formulas,
/// hyperlinks, or clickable paths, and that invalid content is either rejected
/// or reversibly escaped.
/// </summary>
public sealed class XlsxSecurityTests
{
    /// <summary>
    /// Creates a disposable in-memory XLSX with a single worksheet for
    /// cell-writer tests. Returns the document and a writer positioned at
    /// the first sheet's first cell.
    /// </summary>
    private static (SpreadsheetDocument Doc, OpenXmlWriter Writer, MemoryStream Stream)
        CreateTestPackage()
    {
        var stream = new MemoryStream();
        var doc = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook);

        var workbookPart = doc.AddWorkbookPart();
        workbookPart.Workbook = new Workbook();

        var worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
        var writer = OpenXmlWriter.Create(worksheetPart);
        writer.WriteStartElement(new Worksheet());
        writer.WriteStartElement(new SheetData());

        return (doc, writer, stream);
    }

    /// <summary>
    /// Finalize the package so it can be reopened and read.
    /// </summary>
    private static void FinalizePackage(OpenXmlWriter writer, SpreadsheetDocument doc, MemoryStream stream)
    {
        writer.WriteEndElement(); // SheetData
        writer.WriteEndElement(); // Worksheet
        writer.Close();

        var wbPart = doc.WorkbookPart!;
        wbPart.Workbook!.Sheets = new Sheets(
            new Sheet
            {
                Name = "Sheet1",
                SheetId = 1,
                Id = wbPart.GetIdOfPart(wbPart.WorksheetParts.First()),
            });
        wbPart.Workbook.Save();
        doc.Dispose();

        stream.Position = 0;
    }

    [Fact]
    public void Rejects_cell_starting_with_equals()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "=SUM(A1:A10)", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_cell_starting_with_plus()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "+1+2", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_cell_starting_with_minus()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "-1+2", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_cell_starting_with_at()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "@SUM(A1)", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_tab_character()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "hello\tworld", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_cr_character()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "hello\rworld", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_lf_character()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "hello\nworld", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_HYPERLINK_formula()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "HYPERLINK(\"http://evil.com\")", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_http_url()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "http://example.com", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_https_url()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "https://example.com", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_ftp_url()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "ftp://files.example.com", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_file_url()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "file:///etc/passwd", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Rejects_unc_path()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "\\\\server\\share\\file", out _);
        Assert.False(result);
        writer.Dispose();
    }

    [Fact]
    public void Accepts_ordinary_text()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "普通文本 normal text 123", out bool wasEscaped);
        Assert.True(result);
        Assert.False(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Accepts_text_with_hyphen_and_at_embedded()
    {
        var (_, writer, _) = CreateTestPackage();
        // - and @ are only rejected when leading
        bool result = XlsxCellWriter.WriteTextCell(writer, "a-b@c", out bool wasEscaped);
        Assert.True(result);
        Assert.False(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Escapes_xml_invalid_char_0x00()
    {
        var (_, writer, _) = CreateTestPackage();
        string value = "val" + (char)0x00 + "ue";
        bool result = XlsxCellWriter.WriteTextCell(writer, value, out bool wasEscaped);
        Assert.True(result);
        Assert.True(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Escapes_xml_invalid_char_0x02()
    {
        var (_, writer, _) = CreateTestPackage();
        // Use explicit char construction to avoid any compiler/literal encoding issues
        string value = "a" + (char)0x02 + "b";
        bool result = XlsxCellWriter.WriteTextCell(writer, value, out bool wasEscaped);
        Assert.True(result);
        Assert.True(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Escapes_bidirectional_control_LRM()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "text\u200Etext", out bool wasEscaped);
        Assert.True(result);
        Assert.True(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Escapes_bidirectional_control_RLM()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "text\u200Ftext", out bool wasEscaped);
        Assert.True(result);
        Assert.True(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Escapes_source_starting_with_reserved_prefix()
    {
        var (_, writer, _) = CreateTestPackage();
        bool result = XlsxCellWriter.WriteTextCell(writer, "【JSON转义】already_escaped", out bool wasEscaped);
        Assert.True(result);
        Assert.True(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Accepts_32767_char_value()
    {
        var (_, writer, _) = CreateTestPackage();
        string value = new('A', 32_767);
        bool result = XlsxCellWriter.WriteTextCell(writer, value, out bool wasEscaped);
        Assert.True(result);
        Assert.False(wasEscaped);
        writer.Dispose();
    }

    [Fact]
    public void Throws_on_value_exceeding_32767_chars()
    {
        var (_, writer, stream) = CreateTestPackage();
        // 32768 chars should trigger cell limit
        string value = new('A', 32_768);
        Assert.Throws<XlsxCellLimitExceededException>(
            () => XlsxCellWriter.WriteTextCell(writer, value, out _));
        writer.Dispose();
    }

    [Fact]
    public void Throws_when_post_escape_value_exceeds_32767()
    {
        var (_, writer, stream) = CreateTestPackage();
        // A value that, when escaped with 【JSON转义】 prefix + JSON escape,
        // exceeds 32,767 chars. Use 32760 chars of bidir controls (each escapes to \u200E = 6 chars)
        string value = new('\u200E', 32_760);
        Assert.Throws<XlsxCellLimitExceededException>(
            () => XlsxCellWriter.WriteTextCell(writer, value, out _));
        writer.Dispose();
    }

    [Fact]
    public void WriteTextCell_uses_InlineString_type()
    {
        var stream = new MemoryStream();
        using (var doc = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
        {
            var wbPart = doc.AddWorkbookPart();
            wbPart.Workbook = new Workbook();
            var wsPart = wbPart.AddNewPart<WorksheetPart>();
            using (var writer = OpenXmlWriter.Create(wsPart))
            {
                writer.WriteStartElement(new Worksheet());
                writer.WriteStartElement(new SheetData());
                writer.WriteStartElement(new Row());           // cells must be inside a row
                XlsxCellWriter.WriteTextCell(writer, "safe text", out _);
                writer.WriteEndElement(); // Row
                writer.WriteEndElement(); // SheetData
                writer.WriteEndElement(); // Worksheet
            }

            wbPart.Workbook.Sheets = new Sheets(
                new Sheet
                {
                    Name = "Sheet1",
                    SheetId = 1,
                    Id = wbPart.GetIdOfPart(wsPart),
                });
            wbPart.Workbook.Save();
        }

        stream.Position = 0;
        using var reopened = SpreadsheetDocument.Open(stream, false);
        var rows = reopened.WorkbookPart!.WorksheetParts.First()
            .Worksheet!.Descendants<Row>().ToList();
        Assert.Single(rows);

        var cell = rows[0].Elements<Cell>().First();
        Assert.Equal(CellValues.InlineString, cell.DataType?.Value);
        Assert.Null(cell.CellFormula);
    }

    [Fact]
    public void Escaped_cell_contains_json_escape_prefix()
    {
        var stream = new MemoryStream();
        using (var doc = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
        {
            var wbPart = doc.AddWorkbookPart();
            wbPart.Workbook = new Workbook();
            var wsPart = wbPart.AddNewPart<WorksheetPart>();
            using (var writer = OpenXmlWriter.Create(wsPart))
            {
                writer.WriteStartElement(new Worksheet());
                writer.WriteStartElement(new SheetData());
                writer.WriteStartElement(new Row());

                bool wasEscaped;
                XlsxCellWriter.WriteTextCell(writer, "a" + (char)0x00 + "b", out wasEscaped);
                Assert.True(wasEscaped);

                writer.WriteEndElement(); // Row
                writer.WriteEndElement(); // SheetData
                writer.WriteEndElement(); // Worksheet
            }

            wbPart.Workbook.Sheets = new Sheets(
                new Sheet
                {
                    Name = "Sheet1",
                    SheetId = 1,
                    Id = wbPart.GetIdOfPart(wsPart),
                });
            wbPart.Workbook.Save();
        }

        stream.Position = 0;
        using var reopened = SpreadsheetDocument.Open(stream, false);
        var cell = reopened.WorkbookPart!.WorksheetParts.First()
            .Worksheet!.Descendants<Cell>().First();
        var text = cell.InnerText;
        Assert.StartsWith("【JSON转义】", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Escaped_value_is_reversible_json_string()
    {
        var stream = new MemoryStream();
        string original = "a" + (char)0x00 + "b";
        using (var doc = SpreadsheetDocument.Create(stream, SpreadsheetDocumentType.Workbook))
        {
            var wbPart = doc.AddWorkbookPart();
            wbPart.Workbook = new Workbook();
            var wsPart = wbPart.AddNewPart<WorksheetPart>();
            using (var writer = OpenXmlWriter.Create(wsPart))
            {
                writer.WriteStartElement(new Worksheet());
                writer.WriteStartElement(new SheetData());
                writer.WriteStartElement(new Row());

                bool wasEscaped;
                XlsxCellWriter.WriteTextCell(writer, original, out wasEscaped);
                Assert.True(wasEscaped);

                writer.WriteEndElement(); // Row
                writer.WriteEndElement(); // SheetData
                writer.WriteEndElement(); // Worksheet
            }

            wbPart.Workbook.Sheets = new Sheets(
                new Sheet
                {
                    Name = "Sheet1",
                    SheetId = 1,
                    Id = wbPart.GetIdOfPart(wsPart),
                });
            wbPart.Workbook.Save();
        }

        stream.Position = 0;
        using var reopened = SpreadsheetDocument.Open(stream, false);
        var cell = reopened.WorkbookPart!.WorksheetParts.First()
            .Worksheet!.Descendants<Cell>().First();
        var text = cell.InnerText;

        // Strip the prefix and parse as JSON string
        string jsonPart = text["【JSON转义】".Length..];
        var parsed = System.Text.Json.JsonSerializer.Deserialize<string>(jsonPart);
        Assert.Equal(original, parsed);
    }
}
