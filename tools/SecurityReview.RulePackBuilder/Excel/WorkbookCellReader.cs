using System.Text;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace SecurityReview.RulePackBuilder.Excel;

public static class WorkbookCellReader
{
    public const int MaxRowCount = 100_000;
    public const int MaxCellTextLength = 4096;

    /// <summary>
    /// Returns true when the cell contains a formula.
    /// </summary>
    public static bool HasFormula(Cell? cell) => cell?.CellFormula is not null;

    /// <summary>
    /// Extracts the string value from an OpenXml cell, handling shared strings,
    /// inline strings, and plain text.
    /// Returns null when the cell is null, empty, or contains a formula.
    /// </summary>
    public static string? GetStringValue(SpreadsheetDocument doc, Cell? cell)
    {
        if (cell is null)
            return null;

        // Reject formula cells — callers should collect a FormulaCell error instead.
        if (cell.CellFormula is not null)
            return null;

        if (cell.CellValue is null)
            return null;

        if (cell.DataType?.Value == CellValues.SharedString)
        {
            return ReadSharedString(doc, cell.CellValue.Text);
        }

        if (cell.DataType?.Value == CellValues.InlineString)
        {
            return cell.InlineString?.Text?.Text ?? cell.CellValue.Text;
        }

        return cell.CellValue.Text;
    }

    public static int? GetIntValue(SpreadsheetDocument doc, Cell? cell)
    {
        var s = GetStringValue(doc, cell);
        if (s is null)
            return null;
        return int.TryParse(s, out var v) ? v : null;
    }

    public static double? GetDoubleValue(SpreadsheetDocument doc, Cell? cell)
    {
        var s = GetStringValue(doc, cell);
        if (s is null)
            return null;
        return double.TryParse(s, out var v) ? v : null;
    }

    public static bool? GetBoolValue(SpreadsheetDocument doc, Cell? cell)
    {
        var s = GetStringValue(doc, cell);
        if (s is null)
            return null;

        if (string.Equals(s, "1", StringComparison.Ordinal))
            return true;
        if (string.Equals(s, "0", StringComparison.Ordinal))
            return false;

        // Support Chinese and alternative truthy values.
        if (string.Equals(s, "是", StringComparison.Ordinal) ||
            string.Equals(s, "YES", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(s, "否", StringComparison.Ordinal) ||
            string.Equals(s, "NO", StringComparison.OrdinalIgnoreCase))
            return false;

        return bool.TryParse(s, out var b) ? b : null;
    }

    /// <summary>
    /// Returns the 0-based column index from a cell reference (e.g. "A1" → 0, "AB3" → 27).
    /// </summary>
    public static int GetColumnIndex(string? cellRef)
    {
        if (string.IsNullOrEmpty(cellRef))
            return -1;

        int col = 0;
        int i = 0;
        while (i < cellRef.Length && char.IsLetter(cellRef[i]))
        {
            col = col * 26 + (cellRef[i] - 'A' + 1);
            i++;
        }

        return col - 1;
    }

    /// <summary>
    /// Extracts the column letters from a cell reference (e.g. "A1" → "A", "AB3" → "AB").
    /// </summary>
    public static string GetColumnReference(string? cellRef)
    {
        if (string.IsNullOrEmpty(cellRef))
            return string.Empty;

        var sb = new StringBuilder();
        foreach (char c in cellRef)
        {
            if (char.IsLetter(c))
                sb.Append(c);
            else
                break;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Converts a 0-based column index to a column letter (e.g. 0 → "A", 27 → "AB").
    /// </summary>
    public static string IndexToColumnReference(int index)
    {
        var sb = new StringBuilder();
        int col = index + 1;
        while (col > 0)
        {
            col--;
            sb.Insert(0, (char)('A' + (col % 26)));
            col /= 26;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns the cell at the given 0-based column index from a row, or null
    /// if the column is not present.
    /// </summary>
    public static Cell? GetCell(Row row, int columnIndex)
    {
        var colRef = IndexToColumnReference(columnIndex);
        var cellRef = $"{colRef}{row.RowIndex?.Value}";
        return row.Elements<Cell>().FirstOrDefault(
            c => string.Equals(c.CellReference?.Value, cellRef, StringComparison.Ordinal));
    }

    /// <summary>
    /// Reads the header row and builds a map from header text to 0-based column index.
    /// Headers are matched case-sensitively with ordinal comparison.
    /// </summary>
    public static Dictionary<string, int> BuildColumnMap(
        Row headerRow, SpreadsheetDocument doc)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var cell in headerRow.Elements<Cell>())
        {
            // Header cells containing formulas are silently skipped.
            if (cell.CellFormula is not null)
                continue;

            var header = GetStringValue(doc, cell);
            if (string.IsNullOrWhiteSpace(header))
                continue;

            var colIndex = GetColumnIndex(cell.CellReference?.Value);
            if (colIndex >= 0)
            {
                map[header] = colIndex;
            }
        }

        return map;
    }

    // ----------------------------------------------------------------
    //  Structural safety checks
    // ----------------------------------------------------------------

    /// <summary>
    /// Returns true when the row count exceeds <see cref="MaxRowCount"/>,
    /// appending a <see cref="WorkbookValidationError.RowLimitExceeded"/> error.
    /// </summary>
    public static bool CheckRowLimit(
        int rowCount, string sheetName, List<WorkbookValidationError> errors)
    {
        if (rowCount <= MaxRowCount)
            return false;

        errors.Add(new WorkbookValidationError(
            WorkbookValidationError.RowLimitExceeded,
            sheetName, 0, "",
            $"Sheet exceeds the maximum of {MaxRowCount} data rows ({rowCount} found)."));
        return true;
    }

    /// <summary>
    /// Returns true when <paramref name="value"/> exceeds <see cref="MaxCellTextLength"/>,
    /// appending a <see cref="WorkbookValidationError.CellTooLong"/> error.
    /// </summary>
    public static bool CheckCellLength(
        string? value, string sheetName, int rowNum, string column,
        List<WorkbookValidationError> errors)
    {
        if (value is null || value.Length <= MaxCellTextLength)
            return false;

        errors.Add(new WorkbookValidationError(
            WorkbookValidationError.CellTooLong,
            sheetName, rowNum, column,
            $"Cell text exceeds the maximum length of {MaxCellTextLength} characters."));
        return true;
    }

    /// <summary>
    /// Iterates every cell in <paramref name="row"/> and reports a
    /// <see cref="WorkbookValidationError.FormulaCell"/> error for each formula detected.
    /// Returns true when at least one formula was found.
    /// </summary>
    public static bool DetectFormulas(
        Row row, SpreadsheetDocument doc, string sheetName, int rowNum,
        List<WorkbookValidationError> errors)
    {
        var found = false;
        foreach (var cell in row.Elements<Cell>())
        {
            if (cell.CellFormula is null)
                continue;

            var col = GetColumnReference(cell.CellReference?.Value);
            errors.Add(new WorkbookValidationError(
                WorkbookValidationError.FormulaCell,
                sheetName, rowNum, col,
                "Cell contains a formula; formulas are not allowed in rule workbooks."));
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Checks the workbook for external references (linked workbooks or DDE/OLE links)
    /// and reports an <see cref="WorkbookValidationError.ExternalLink"/> error when any exist.
    /// Returns true when external links were detected.
    /// </summary>
    public static bool DetectExternalLinks(
        SpreadsheetDocument doc, string sheetName, List<WorkbookValidationError> errors)
    {
        var wbPart = doc.WorkbookPart;
        if (wbPart is null)
            return false;

        var found = false;

        // External workbook references (linked spreadsheets).
        if (wbPart.ExternalWorkbookParts?.Any() == true)
        {
            errors.Add(new WorkbookValidationError(
                WorkbookValidationError.ExternalLink,
                sheetName, 0, "",
                "Workbook contains external links to other spreadsheets."));
            found = true;
        }

        // Workbook-level external references (DDE / OLE links).
        var externalRefs = wbPart.Workbook?.ExternalReferences;
        if (externalRefs is not null && externalRefs.Any())
        {
            errors.Add(new WorkbookValidationError(
                WorkbookValidationError.ExternalLink,
                sheetName, 0, "",
                "Workbook contains external references (DDE/OLE)."));
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Checks for an embedded VBA project and reports a
    /// <see cref="WorkbookValidationError.MacroPart"/> error when present.
    /// Returns true when a VBA / macro part was detected.
    /// </summary>
    public static bool DetectMacros(
        SpreadsheetDocument doc, string sheetName, List<WorkbookValidationError> errors)
    {
        if (doc.WorkbookPart?.VbaProjectPart is null)
            return false;

        errors.Add(new WorkbookValidationError(
            WorkbookValidationError.MacroPart,
            sheetName, 0, "",
            "Workbook contains embedded VBA macros; macros are not allowed in rule workbooks."));
        return true;
    }

    // ----------------------------------------------------------------
    //  Internal helpers
    // ----------------------------------------------------------------

    private static string? ReadSharedString(SpreadsheetDocument doc, string indexText)
    {
        var sst = doc.WorkbookPart?.SharedStringTablePart?.SharedStringTable;
        if (sst is null)
            return null;

        if (!int.TryParse(indexText, out var index))
            return null;

        if (index < 0 || index >= sst.Count())
            return null;

        return sst.ElementAt(index).InnerText;
    }
}
