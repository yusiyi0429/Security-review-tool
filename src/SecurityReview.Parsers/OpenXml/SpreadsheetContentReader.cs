using System.Globalization;
using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using SecurityReview.Domain;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Reads cell content, formulas, comments, and metadata from SpreadsheetML parts.
/// </summary>
public static class SpreadsheetContentReader
{
    public static List<ParserEvent.ChunkProduced> Read(
        SpreadsheetDocument doc,
        ScanId scanId,
        JobId jobId,
        string virtualPath)
    {
        ArgumentNullException.ThrowIfNull(doc);

        var chunks = new List<ParserEvent.ChunkProduced>();
        long sequence = 0;

        var sharedStrings = BuildSharedStringTable(doc);

        // Read defined names
        if (doc.WorkbookPart != null)
        {
            ReadDefinedNames(doc.WorkbookPart, jobId, virtualPath, ref sequence, chunks);
        }

        // Read each worksheet
        if (doc.WorkbookPart?.Workbook?.Sheets != null)
        {
            foreach (Sheet sheet in doc.WorkbookPart.Workbook.Sheets!.Cast<Sheet>())
            {
                string state = sheet.State?.ToString() ?? "visible";

                var worksheetPart = (WorksheetPart?)doc.WorkbookPart.GetPartById(sheet.Id?.Value ?? "");
                if (worksheetPart == null) continue;

                string sheetName = sheet.Name?.Value ?? sheet.SheetId?.Value.ToString(CultureInfo.InvariantCulture) ?? "Sheet";

                ReadWorksheet(worksheetPart, sheetName, state, sharedStrings,
                    jobId, virtualPath, ref sequence, chunks);

                ReadSheetComments(worksheetPart, sheetName,
                    jobId, virtualPath, ref sequence, chunks);
            }
        }

        return chunks;
    }

    private static Dictionary<int, string> BuildSharedStringTable(SpreadsheetDocument doc)
    {
        var table = new Dictionary<int, string>();
        try
        {
            var sstPart = doc.WorkbookPart?.GetPartsOfType<SharedStringTablePart>().FirstOrDefault();
            if (sstPart == null) return table;

            using var stream = sstPart.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            using var reader = XmlReader.Create(stream,
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

            const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            int index = 0;

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.LocalName == "si" && reader.NamespaceURI == smlNs)
                {
                    table[index++] = ReadSharedStringItem(reader);
                }
            }
        }
        catch
        {
        }

        return table;
    }

    private static string ReadSharedStringItem(XmlReader reader)
    {
        var parts = new List<string>();
        int depth = reader.Depth;
        const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

        while (reader.Read() &&
               !(reader.NodeType == XmlNodeType.EndElement &&
                 reader.LocalName == "si" && reader.Depth == depth))
        {
            if (reader.NodeType == XmlNodeType.Element &&
                reader.LocalName == "t" && reader.NamespaceURI == smlNs)
            {
                reader.Read();
                if (reader.NodeType == XmlNodeType.Text)
                    parts.Add(reader.Value);
            }
        }

        return string.Join("", parts);
    }

    private static void ReadWorksheet(
        WorksheetPart worksheetPart, string sheetName, string state,
        Dictionary<int, string> sharedStrings,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            using var stream = worksheetPart.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            using var reader = XmlReader.Create(stream,
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

            const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            bool inSheetData = false;
            string? currentCellRef = null;
            string? currentCellType = null;
            int currentRow = 0;
            bool rowHidden = false;

            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element || reader.NamespaceURI != smlNs)
                    continue;

                switch (reader.LocalName)
                {
                    case "sheetData":
                        inSheetData = true;
                        break;

                    case "row" when inSheetData:
                        _ = int.TryParse(reader.GetAttribute("r"), out currentRow);
                        string? hidden = reader.GetAttribute("hidden");
                        rowHidden = hidden == "1" || string.Equals(hidden, "true", StringComparison.OrdinalIgnoreCase);
                        break;

                    case "c" when inSheetData:
                        currentCellRef = reader.GetAttribute("r");
                        currentCellType = reader.GetAttribute("t");
                        ReadCell(reader, sheetName, currentCellRef, currentCellType,
                            currentRow, rowHidden, sharedStrings,
                            jobId, virtualPath, ref sequence, chunks);
                        break;
                }
            }

            // Emit hidden sheet metadata
            if (!string.Equals(state, "visible", StringComparison.OrdinalIgnoreCase))
            {
                var metaChunk = new ContentChunk(
                    1, jobId, sequence++, virtualPath,
                    "openxml", ContentKind.Metadata,
                    "utf-8", $"Sheet {sheetName} state: {state}",
                    0, 0, [], false);
                chunks.Add(new ParserEvent.ChunkProduced(metaChunk));
            }
        }
        catch
        {
        }
    }

    private static void ReadCell(
        XmlReader reader, string sheetName, string? cellRef, string? cellType,
        int row, bool rowHidden,
        Dictionary<int, string> sharedStrings,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        string? valueText = null;
        string? formulaText = null;
        int depth = reader.Depth;
        const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

        while (reader.Read() &&
               !(reader.NodeType == XmlNodeType.EndElement &&
                 reader.LocalName == "c" && reader.Depth == depth))
        {
            if (reader.NodeType != XmlNodeType.Element || reader.NamespaceURI != smlNs)
                continue;

            switch (reader.LocalName)
            {
                case "v":
                    reader.Read();
                    if (reader.NodeType == XmlNodeType.Text)
                        valueText = reader.Value;
                    break;

                case "f":
                    reader.Read();
                    if (reader.NodeType == XmlNodeType.Text)
                        formulaText = reader.Value;
                    break;

                case "is":
                    valueText = ReadInlineString(reader);
                    break;
            }
        }

        string? cellValue = ResolveCellValue(valueText, cellType, sharedStrings);
        string cellDisplay = cellRef ?? $"R{row}";

        if (!string.IsNullOrEmpty(cellValue))
        {
            var chunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Text,
                "utf-8", $"[{sheetName}!{cellDisplay}] {cellValue}",
                0, 0, [], false);
            chunks.Add(new ParserEvent.ChunkProduced(chunk));
        }

        // Emit formula as literal text (never evaluated)
        if (!string.IsNullOrEmpty(formulaText))
        {
            var chunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Metadata,
                "utf-8", $"[{sheetName}!{cellDisplay}] Formula: {formulaText}",
                0, 0, [], false);
            chunks.Add(new ParserEvent.ChunkProduced(chunk));
        }

        // Hidden row metadata
        if (rowHidden && !string.IsNullOrEmpty(cellValue))
        {
            var hiddenChunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Metadata,
                "utf-8", $"[{sheetName}!{cellDisplay}] row_hidden:true {cellValue}",
                0, 0, [], false);
            chunks.Add(new ParserEvent.ChunkProduced(hiddenChunk));
        }
    }

    private static string? ResolveCellValue(
        string? valueText, string? cellType, Dictionary<int, string> sharedStrings)
    {
        if (string.IsNullOrEmpty(valueText)) return null;

        if (cellType == "s" && int.TryParse(valueText, out int sstIndex))
            return sharedStrings.TryGetValue(sstIndex, out string? s) ? s : $"[shared_string:{sstIndex}]";

        if (cellType == "b")
            return valueText == "1" ? "TRUE" : "FALSE";

        if (cellType == "e")
            return $"[error:{valueText}]";

        return valueText;
    }

    private static string ReadInlineString(XmlReader reader)
    {
        var parts = new List<string>();
        int depth = reader.Depth;
        const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

        while (reader.Read() &&
               !(reader.NodeType == XmlNodeType.EndElement &&
                 reader.LocalName == "is" && reader.Depth == depth))
        {
            if (reader.NodeType == XmlNodeType.Element &&
                reader.LocalName == "t" && reader.NamespaceURI == smlNs)
            {
                reader.Read();
                if (reader.NodeType == XmlNodeType.Text)
                    parts.Add(reader.Value);
            }
        }

        return string.Join("", parts);
    }

    private static void ReadDefinedNames(
        WorkbookPart workbookPart,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            using var stream = workbookPart.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            using var reader = XmlReader.Create(stream,
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

            const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.LocalName == "definedName" && reader.NamespaceURI == smlNs)
                {
                    string? name = reader.GetAttribute("name");
                    reader.Read();
                    string? formula = reader.NodeType == XmlNodeType.Text ? reader.Value : null;

                    if (!string.IsNullOrEmpty(name))
                    {
                        var chunk = new ContentChunk(
                            1, jobId, sequence++, virtualPath,
                            "openxml", ContentKind.Metadata,
                            "utf-8", $"DefinedName: {name} = {formula ?? ""}",
                            0, 0, [], false);
                        chunks.Add(new ParserEvent.ChunkProduced(chunk));
                    }
                }
            }
        }
        catch
        {
        }
    }

    private static void ReadSheetComments(
        WorksheetPart worksheetPart, string sheetName,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            foreach (var commentsPart in worksheetPart.GetPartsOfType<WorksheetCommentsPart>())
            {
                using var stream = commentsPart.GetStream(FileMode.Open, FileAccess.Read);
                if (stream.CanSeek) stream.Position = 0;

                using var reader = XmlReader.Create(stream,
                    new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

                const string smlNs = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
                string? commentRef = null;

                while (reader.Read())
                {
                    if (reader.NodeType == XmlNodeType.Element &&
                        reader.LocalName == "comment" && reader.NamespaceURI == smlNs)
                    {
                        commentRef = reader.GetAttribute("ref");
                    }

                    if (reader.NodeType == XmlNodeType.Element &&
                        reader.LocalName == "t" && reader.NamespaceURI == smlNs)
                    {
                        reader.Read();
                        if (reader.NodeType == XmlNodeType.Text && !string.IsNullOrEmpty(reader.Value))
                        {
                            var chunk = new ContentChunk(
                                1, jobId, sequence++, virtualPath,
                                "openxml", ContentKind.Text,
                                "utf-8", $"[{sheetName}!{commentRef ?? "?"}] Comment: {reader.Value}",
                                0, 0, [], false);
                            chunks.Add(new ParserEvent.ChunkProduced(chunk));
                        }
                    }
                }
            }
        }
        catch
        {
        }
    }
}
