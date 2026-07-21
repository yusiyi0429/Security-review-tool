using System.Globalization;
using System.Text;
using System.Text.Json;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Spreadsheet;

namespace SecurityReview.Infrastructure.Reporting;

/// <summary>
/// Safe text-cell writer for OpenXmlWriter streaming. Every cell is emitted as
/// <c>CellValues.InlineString</c> with no formula, hyperlink, or clickable path.
/// Invalid content is either rejected or reversibly escaped with a
/// <c>【JSON转义】</c> prefix.
/// </summary>
public static class XlsxCellWriter
{
    private const string EscapePrefix = "【JSON转义】";
    private const int MaxCellLength = 32_767;

    /// <summary>
    /// Write a single text cell. Returns <c>true</c> on success.
    /// Returns <c>false</c> when the value contains a rejected pattern
    /// (formula, control characters, URL, UNC, HYPERLINK).
    /// Sets <paramref name="wasEscaped"/> when XML-invalid or bidirectional
    /// characters were present and the value was JSON-escaped. Throws
    /// <see cref="XlsxCellLimitExceededException"/> when the final cell value
    /// exceeds 32,767 UTF-16 code units.
    /// </summary>
    public static bool WriteTextCell(
        OpenXmlWriter writer,
        string value,
        out bool wasEscaped)
    {
        wasEscaped = false;

        if (value is null)
        {
            WriteEmptyCell(writer);
            return true;
        }

        // --- reject dangerous prefixes / patterns ---
        if (!IsAcceptableText(value))
            return false;

        // --- detect characters requiring escape ---
        bool needsEscape = RequiresJsonEscape(value);

        string cellValue;
        if (needsEscape)
        {
            cellValue = EscapePrefix + JsonSerializer.Serialize(value);
            wasEscaped = true;
        }
        else
        {
            cellValue = value;
        }

        if (cellValue.Length > MaxCellLength)
            throw new XlsxCellLimitExceededException(
                $"Cell value length {cellValue.Length} exceeds the Excel limit of {MaxCellLength} characters.");

        WriteInlineStringCell(writer, cellValue);
        return true;
    }

    /// <summary>
    /// Writes a text cell by calling <see cref="WriteTextCell"/> and throws
    /// <see cref="InvalidOperationException"/> with rejection detail on failure.
    /// </summary>
    public static void WriteTextCellOrThrow(
        OpenXmlWriter writer, string value, out bool wasEscaped)
    {
        if (!WriteTextCell(writer, value, out wasEscaped))
        {
            throw new InvalidOperationException(
                $"Cell value was rejected by XlsxCellWriter. " +
                $"Value preview: {TruncateForMessage(value)}");
        }
    }

    /// <summary>
    /// Write a text cell without any escaping or rejection — caller guarantees
    /// the value is safe.
    /// </summary>
    public static void WriteSafeTextCell(OpenXmlWriter writer, string value)
    {
        if (value.Length > MaxCellLength)
            throw new XlsxCellLimitExceededException(
                $"Cell value length {value.Length} exceeds the Excel limit.");

        WriteInlineStringCell(writer, value);
    }

    // ---------------------------------------------------------------
    // internal helpers
    // ---------------------------------------------------------------

    private static bool IsAcceptableText(string value)
    {
        if (value.Length == 0)
            return true;

        // Leading formula characters
        char first = value[0];
        if (first is '=' or '+' or '-' or '@')
            return false;

        // Contains HYPERLINK formula text
        if (value.Contains("HYPERLINK", StringComparison.Ordinal))
            return false;

        // URL schemes (case-insensitive prefix)
        if (StartsWithUrlScheme(value))
            return false;

        // UNC path
        if (value.StartsWith("\\\\", StringComparison.Ordinal))
            return false;

        // Tab, CR, LF anywhere
        foreach (char c in value)
        {
            if (c is '\t' or '\r' or '\n')
                return false;
        }

        return true;
    }

    private static bool StartsWithUrlScheme(string value)
    {
        ReadOnlySpan<char> span = value.AsSpan();
        if (span.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return true;
        if (span.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return true;
        if (span.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase)) return true;
        if (span.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Returns true when the value contains XML-invalid characters,
    /// bidirectional control characters, or starts with the escape prefix.
    /// </summary>
    internal static bool RequiresJsonEscape(string value)
    {
        // Source starts with the reserved escape prefix → must escape to avoid ambiguity
        if (value.StartsWith(EscapePrefix, StringComparison.Ordinal))
            return true;

        foreach (char c in value)
        {
            if (IsInvalidXmlChar(c) || IsBidirectionalControl(c))
                return true;
        }

        return false;
    }

    private static bool IsInvalidXmlChar(char c)
    {
        // XML 1.0 invalid character ranges
        return c switch
        {
            // Control characters below 0x20 except \t (0x09), \n (0x0A), \r (0x0D)
            >= '\x00' and <= '\x08' => true,
            '\x0B' or '\x0C' => true,
            >= '\x0E' and <= '\x1F' => true,
            // Unicode non-characters
            '\uFFFE' or '\uFFFF' => true,
            _ => false,
        };
    }

    private static bool IsBidirectionalControl(char c)
    {
        return c switch
        {
            '\u200E' => true, // LRM
            '\u200F' => true, // RLM
            '\u202A' => true, // LRE
            '\u202B' => true, // RLE
            '\u202C' => true, // PDF
            '\u202D' => true, // LRO
            '\u202E' => true, // RLO
            '\u2066' => true, // LRI
            '\u2067' => true, // RLI
            '\u2068' => true, // FSI
            '\u2069' => true, // PDI
            _ => false,
        };
    }

    private static void WriteInlineStringCell(OpenXmlWriter writer, string text)
    {
        writer.WriteStartElement(new Cell
        {
            DataType = CellValues.InlineString,
        });

        writer.WriteStartElement(new InlineString());
        writer.WriteElement(new Text(text));
        writer.WriteEndElement(); // InlineString
        writer.WriteEndElement(); // Cell
    }

    private static void WriteEmptyCell(OpenXmlWriter writer)
    {
        writer.WriteStartElement(new Cell());
        writer.WriteEndElement();
    }

    internal static string TruncateForMessage(string value)
    {
        if (value is null) return "null";
        if (value.Length <= 50) return value;
        return value[..50] + "...";
    }
}

/// <summary>
/// Thrown when a cell value exceeds Excel's 32,767-character limit.
/// Callers must abort the entire export atomically.
/// </summary>
public class XlsxCellLimitExceededException : Exception
{
    public XlsxCellLimitExceededException(string message) : base(message) { }
}
