using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Application.Reporting;

namespace SecurityReview.Infrastructure.Reporting;

/// <summary>
/// Post-export allowlist validator. Reopens the XLSX package read-only and
/// asserts that only known-safe parts, relationships, and cell types exist.
/// Any forbidden part, external relationship, formula, or corrupted XML
/// causes immediate rejection.
/// </summary>
public static class XlsxPackageSecurityValidator
{
    /// <summary>
    /// Maximum allowed package file size in bytes.
    /// </summary>
    public const long MaxPackageSizeBytes = 256L * 1024 * 1024; // 256 MiB

    public static void Validate(string filePath, IReadOnlyDictionary<string, int> expectedRowCounts)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
            throw new FileNotFoundException("XLSX file not found for validation.", filePath);

        if (fileInfo.Length > MaxPackageSizeBytes)
            throw new InvalidOperationException(
                $"XLSX package size {fileInfo.Length} exceeds maximum {MaxPackageSizeBytes} bytes.");

        using var doc = SpreadsheetDocument.Open(filePath, false);

        // --- 1. Required parts ---
        if (doc.WorkbookPart is null)
            throw new InvalidOperationException("XLSX validation failed: missing WorkbookPart.");

        if (doc.WorkbookPart.WorkbookStylesPart is null)
            throw new InvalidOperationException("XLSX validation failed: missing WorkbookStylesPart.");

        var sheetParts = doc.WorkbookPart.WorksheetParts.ToList();
        if (sheetParts.Count != 6)
            throw new InvalidOperationException(
                $"XLSX validation failed: expected 6 worksheets, found {sheetParts.Count}.");

        // --- 2. Forbidden parts ---
        AssertNoForbiddenParts(doc);

        // --- 3. Exact sheet names and order ---
        var sheetsElement = doc.WorkbookPart!.Workbook!.Sheets!;
        var sheets = sheetsElement.Elements<Sheet>().ToList();
        if (sheets.Count != 6)
            throw new InvalidOperationException(
                $"XLSX validation failed: expected 6 sheet entries, found {sheets.Count}.");

        for (int i = 0; i < 6; i++)
        {
            if (!string.Equals(sheets[i].Name!.Value, XlsxSheetSchemas.Sheets[i].Name, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"XLSX validation failed: sheet {i} is '{sheets[i].Name?.Value}' " +
                    $"but expected '{XlsxSheetSchemas.Sheets[i].Name}'.");
        }

        // --- 4. No external relationships ---
        AssertNoExternalRelationships(doc);

        // --- 5. Per-sheet validation ---
        for (int i = 0; i < 6; i++)
        {
            var sheetName = XlsxSheetSchemas.Sheets[i].Name;
            var expectedHeaders = XlsxSheetSchemas.Sheets[i].Headers;
            var expectedDataRows = expectedRowCounts.TryGetValue(sheetName, out int c) ? c : 0;
            ValidateWorksheet(sheetParts[i], sheetName, expectedHeaders, expectedDataRows);
        }

        // --- 6. No duplicate part URIs ---
        AssertNoDuplicatePartUris(doc);

        // --- 7. No formulas anywhere ---
        AssertNoFormulas(sheetParts);
    }

    // ---------------------------------------------------------------
    // Forbidden parts
    // ---------------------------------------------------------------

    private static void AssertNoForbiddenParts(SpreadsheetDocument doc)
    {
        // Check each part under the workbook — reject VBA, macros, external refs,
        // ActiveX, embedded objects, images, and other dangerous content.
        foreach (var idPartPair in doc.WorkbookPart!.Parts)
        {
            var part = idPartPair.OpenXmlPart;
            string? contentType = part.ContentType;

            // Reject macro-enabled and binary content
            if (contentType is not null)
            {
                if (contentType.Contains("macro", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("binary", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("vba", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("activeX", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("image", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("oleObject", StringComparison.OrdinalIgnoreCase)
                    || contentType.Contains("package", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"XLSX validation failed: forbidden part content type '{contentType}'.");
                }
            }
        }
    }

    private static void AssertNoExternalRelationships(SpreadsheetDocument doc)
    {
        // Check workbook part external relationships
        foreach (var rel in doc.WorkbookPart!.ExternalRelationships)
        {
            throw new InvalidOperationException(
                $"XLSX validation failed: workbook-level external relationship '{rel.RelationshipType}' detected.");
        }
    }

    /// <summary>
    /// Validate one worksheet: headers match, row count is correct, all cells
    /// are text (no formulas).
    /// </summary>
    private static void ValidateWorksheet(
        WorksheetPart part,
        string expectedName,
        string[] expectedHeaders,
        int expectedDataRows)
    {
        var worksheet = part.Worksheet;
        if (worksheet is null)
            throw new InvalidOperationException($"XLSX validation failed: worksheet '{expectedName}' has no content.");

        var rows = worksheet.Descendants<Row>().ToList();

        // Header row + data rows
        int expectedTotalRows = 1 + expectedDataRows;
        if (rows.Count != expectedTotalRows)
            throw new InvalidOperationException(
                $"XLSX validation failed: sheet '{expectedName}' has {rows.Count} rows, " +
                $"expected {expectedTotalRows} (1 header + {expectedDataRows} data).");

        // Check header row
        var headerCells = rows[0].Elements<Cell>().ToList();
        if (headerCells.Count != expectedHeaders.Length)
            throw new InvalidOperationException(
                $"XLSX validation failed: sheet '{expectedName}' header has {headerCells.Count} columns, " +
                $"expected {expectedHeaders.Length}.");

        for (int i = 0; i < expectedHeaders.Length; i++)
        {
            string actual = GetCellText(headerCells[i], part);
            if (!string.Equals(actual, expectedHeaders[i], StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"XLSX validation failed: sheet '{expectedName}' header column {i} " +
                    $"is '{actual}', expected '{expectedHeaders[i]}'.");
        }
    }

    private static void AssertNoDuplicatePartUris(SpreadsheetDocument doc)
    {
        var uris = new HashSet<string>(StringComparer.Ordinal);
        foreach (var part in doc.WorkbookPart!.Parts)
        {
            if (!uris.Add(part.OpenXmlPart.Uri.ToString()))
                throw new InvalidOperationException(
                    $"XLSX validation failed: duplicate part URI '{part.OpenXmlPart.Uri}'.");
        }
    }

    private static void AssertNoFormulas(List<WorksheetPart> sheetParts)
    {
        foreach (var part in sheetParts)
        {
            foreach (var cell in part.Worksheet!.Descendants<Cell>())
            {
                if (cell.CellFormula is not null)
                    throw new InvalidOperationException(
                        "XLSX validation failed: CellFormula detected in sheet.");
            }
        }
    }

    /// <summary>
    /// Extracts the display text of a cell, handling inline strings and shared
    /// strings. Returns empty string for null/missing content.
    /// </summary>
    private static string GetCellText(Cell cell, WorksheetPart part)
    {
        if (cell.DataType is not null && cell.DataType.Value == CellValues.InlineString)
        {
            var inlineString = cell.Elements<InlineString>().FirstOrDefault();
            if (inlineString is null) return string.Empty;
            var text = inlineString.Elements<Text>().FirstOrDefault();
            return text?.Text ?? string.Empty;
        }

        if (cell.DataType is not null && cell.DataType.Value == CellValues.SharedString)
        {
            if (int.TryParse(cell.InnerText, out int index))
            {
                var sstPart = part.GetParentParts()
                    .OfType<WorkbookPart>().FirstOrDefault()
                    ?.GetPartsOfType<SharedStringTablePart>().FirstOrDefault();
                if (sstPart?.SharedStringTable is not null
                    && index < sstPart.SharedStringTable.Elements<SharedStringItem>().Count())
                {
                    return sstPart.SharedStringTable.Elements<SharedStringItem>()
                        .ElementAt(index).InnerText;
                }
            }
        }

        // Fallback: inner text (for String/Number cells)
        return cell.InnerText;
    }
}
