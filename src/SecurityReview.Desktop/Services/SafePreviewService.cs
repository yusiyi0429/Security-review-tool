using System.Globalization;
using System.Text;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Desktop.Services;

/// <summary>
/// Produces bounded, read-only text fragments around a source locator.
/// Never opens input with shell, Office, PDF, or browser controls.
/// All output is plain text suitable for a read-only TextBox.
/// </summary>
public sealed class SafePreviewService
{
    // Fragment bounds
    private const int MaxTextLines = 20;
    private const int MaxTextBytes = 65_536; // 64 KiB
    private const int MaxTableRows = 10;
    private const int MaxBinaryBytes = 256;

    /// <summary>
    /// Produces a bounded text preview fragment around the given locator.
    /// Returns the fragment lines and the highlight range (line index + char range).
    /// </summary>
    public static SafePreviewFragment PreviewText(string fullText, SourceLocator locator)
    {
        ArgumentNullException.ThrowIfNull(fullText);
        ArgumentNullException.ThrowIfNull(locator);

        if (fullText.Length == 0)
        {
            return new SafePreviewFragment(
                Array.Empty<SafePreviewLine>(), -1, 0, 0, 0, 0,
                locator.ToCanonicalDisplay());
        }

        var (lineOffset, byteOffset, byteLength) = ResolveTextPosition(locator, fullText);

        string[] lines = fullText.Split('\n');
        if (lines.Length > 0 && lines[^1].Length == 0)
            lines = lines[..^1];
        int targetLine = lineOffset >= 0 && lineOffset < lines.Length ? (int)lineOffset : 0;

        int startLine = Math.Max(0, targetLine - MaxTextLines / 2);
        int endLine = Math.Min(lines.Length, startLine + MaxTextLines);
        if (endLine - startLine < MaxTextLines && startLine > 0)
            startLine = Math.Max(0, endLine - MaxTextLines);

        var fragmentLines = new List<SafePreviewLine>();
        int totalBytes = 0;
        int highlightLineIndex = -1;
        int highlightCharStart = 0;
        int highlightCharEnd = 0;

        for (int i = startLine; i < endLine; i++)
        {
            string line = lines[i];
            byte[] lineBytes = Encoding.UTF8.GetBytes(line + '\n');
            if (totalBytes + lineBytes.Length > MaxTextBytes && fragmentLines.Count > 0)
                break;

            fragmentLines.Add(new SafePreviewLine(i, line.TrimEnd('\r')));
            totalBytes += lineBytes.Length;

            if (i == targetLine)
            {
                highlightLineIndex = fragmentLines.Count - 1;

                // Compute char-level highlight within the line for TextLocator/JsonLocator
                if (locator is SourceLocator.TextLocator tl)
                {
                    highlightCharStart = Math.Clamp((int)tl.Column, 0, line.Length);
                    highlightCharEnd = Math.Min(line.Length, highlightCharStart + (int)tl.ByteLength);
                }
                else if (locator is SourceLocator.JsonLocator jl)
                {
                    (highlightCharStart, highlightCharEnd) = ResolveUtf8CharRange(
                        line, byteOffset, jl.ByteLength);
                }
                else
                {
                    highlightCharStart = 0;
                    highlightCharEnd = 0;
                }
            }
        }

        long truncatedBefore = startLine;
        long truncatedAfter = lines.Length - (startLine + fragmentLines.Count);

        return new SafePreviewFragment(
            fragmentLines,
            highlightLineIndex,
            highlightCharStart,
            highlightCharEnd,
            truncatedBefore,
            truncatedAfter,
            locator.ToCanonicalDisplay());
    }

    /// <summary>
    /// Produces a bounded table preview (max 10 rows) around the cell locator.
    /// </summary>
    public static SafeTablePreview PreviewTable(IReadOnlyList<IReadOnlyList<string>> rows, SourceLocator.CellLocator locator)
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(locator);

        int targetRow = FindRowIndex(rows, locator.Sheet);
        int startRow = Math.Max(0, targetRow - MaxTableRows / 2);
        int endRow = Math.Min(rows.Count, startRow + MaxTableRows);

        var fragment = new List<IReadOnlyList<string>>();
        for (int i = startRow; i < endRow; i++)
            fragment.Add(rows[i]);

        int highlightRow = targetRow >= startRow && targetRow < endRow ? targetRow - startRow : -1;
        string highlightCell = locator.Cell;

        return new SafeTablePreview(fragment, highlightRow, highlightCell, startRow, rows.Count - endRow);
    }

    /// <summary>
    /// Produces a bounded binary hex/text preview (max 256 bytes).
    /// </summary>
    public static SafeBinaryPreview PreviewBinary(byte[] data, SourceLocator.BinaryLocator locator)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(locator);

        long start = Math.Max(0, locator.ByteOffset);
        long end = Math.Min(data.Length, start + Math.Max(MaxBinaryBytes, locator.ByteLength));
        int length = (int)(end - start);

        var hexLines = new List<SafeBinaryLine>();
        var textLines = new List<string>();

        for (int i = 0; i < length; i += 16)
        {
            int chunkSize = Math.Min(16, length - i);
            var chunk = data.AsSpan((int)start + i, chunkSize);

            var hex = new StringBuilder(chunkSize * 3);
            var text = new StringBuilder(chunkSize);
            for (int j = 0; j < chunkSize; j++)
            {
                hex.Append(chunk[j].ToString("X2", CultureInfo.InvariantCulture));
                hex.Append(' ');
                char c = (char)chunk[j];
                text.Append(char.IsControl(c) ? '.' : c);
            }

            hexLines.Add(new SafeBinaryLine(start + i, hex.ToString().TrimEnd()));
            textLines.Add(text.ToString());
        }

        return new SafeBinaryPreview(
            hexLines,
            textLines,
            start,
            length,
            data.Length - end);
    }

    /// <summary>
    /// Produces a plain-text block extracted from a PDF page/block locator.
    /// Returns the block text; caller is responsible for rendering in a plain TextBox.
    /// </summary>
    public static string PreviewPdfBlock(string pageText, SourceLocator.PdfLocator locator)
    {
        // The caller provides the extracted page text block.
        // We truncate to MaxTextBytes and MaxTextLines.
        if (string.IsNullOrEmpty(pageText)) return string.Empty;

        string[] lines = pageText.Split('\n');
        int lineCount = Math.Min(lines.Length, MaxTextLines);
        int totalBytes = 0;
        var result = new StringBuilder();

        for (int i = 0; i < lineCount && totalBytes < MaxTextBytes; i++)
        {
            string line = lines[i].TrimEnd('\r');
            byte[] lineBytes = Encoding.UTF8.GetBytes(line + Environment.NewLine);
            if (totalBytes + lineBytes.Length > MaxTextBytes) break;
            result.AppendLine(line);
            totalBytes += lineBytes.Length;
        }

        return result.ToString();
    }

    /// <summary>
    /// Produces a bounded OCI entry preview.
    /// </summary>
    public static SafePreviewFragment PreviewOciEntry(string entryContent, SourceLocator.OciLocator locator)
    {
        return PreviewText(entryContent, new SourceLocator.TextLocator(0, 0, 0, 0));
    }

    /// <summary>
    /// Resolves line/byte position from a SourceLocator.
    /// </summary>
    private static (long Line, long ByteStart, long ByteLength) ResolveTextPosition(SourceLocator locator, string fullText)
    {
        switch (locator)
        {
            case SourceLocator.TextLocator tl:
                return (tl.Line, tl.ByteStart, tl.ByteLength);
            case SourceLocator.JsonLocator jl:
                {
                    // Search for the JSON pointer in the text then estimate line
                    int lineIdx = 0;
                    long byteCount = 0;
                    foreach (string ln in fullText.Split('\n'))
                    {
                        long nextByteCount = byteCount + Encoding.UTF8.GetByteCount(ln + "\n");
                        if (byteCount <= jl.ByteStart && nextByteCount > jl.ByteStart)
                            return (lineIdx, jl.ByteStart - byteCount, jl.ByteLength);
                        byteCount = nextByteCount;
                        lineIdx++;
                    }
                    return (0, jl.ByteStart, jl.ByteLength);
                }
            case SourceLocator.PdfLocator pl:
                return (pl.Page, 0, 0);
            default:
                return (0, 0, 0);
        }
    }

    private static (int Start, int End) ResolveUtf8CharRange(
        string text, long byteStart, long byteLength)
    {
        if (byteStart < 0 || byteLength <= 0)
            return (0, 0);

        int start = Utf8ByteOffsetToCharIndex(text, byteStart);
        int end = Utf8ByteOffsetToCharIndex(text, byteStart + byteLength);
        return (start, Math.Max(start, end));
    }

    private static int Utf8ByteOffsetToCharIndex(string text, long byteOffset)
    {
        if (byteOffset <= 0)
            return 0;

        long consumed = 0;
        for (int i = 0; i < text.Length; i++)
        {
            int charLength = char.IsHighSurrogate(text[i]) &&
                i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            int bytes = Encoding.UTF8.GetByteCount(text.AsSpan(i, charLength));
            if (consumed + bytes > byteOffset)
                return i;
            consumed += bytes;
            if (consumed == byteOffset)
                return i + charLength;
            i += charLength - 1;
        }
        return text.Length;
    }

    private static int FindRowIndex(IReadOnlyList<IReadOnlyList<string>> rows, string sheetName)
    {
        // Sheet name might match the first cell; find the row index
        for (int i = 0; i < rows.Count; i++)
        {
            var row = rows[i];
            if (row.Count > 0 && row[0].Contains(sheetName, StringComparison.OrdinalIgnoreCase))
                return i;
        }
        return 0;
    }
}

// ---------------------------------------------------------------------------
// Preview DTOs — immutable, plain text only
// ---------------------------------------------------------------------------

public sealed record SafePreviewFragment(
    IReadOnlyList<SafePreviewLine> Lines,
    int HighlightLineIndex,
    int HighlightCharStart,
    int HighlightCharEnd,
    long TruncatedBefore,
    long TruncatedAfter,
    string LocatorDisplay);

public sealed record SafePreviewLine(int LineNumber, string Text);

public sealed record SafeTablePreview(
    IReadOnlyList<IReadOnlyList<string>> Rows,
    int HighlightRow,
    string HighlightCell,
    long TruncatedBefore,
    long TruncatedAfter);

public sealed record SafeBinaryPreview(
    IReadOnlyList<SafeBinaryLine> HexLines,
    IReadOnlyList<string> TextLines,
    long ByteOffset,
    int ByteLength,
    long TruncatedAfter);

public sealed record SafeBinaryLine(long Offset, string Hex);
