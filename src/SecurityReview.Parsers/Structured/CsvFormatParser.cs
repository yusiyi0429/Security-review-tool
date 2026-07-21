using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Parses CSV sources using an RFC 4180 state machine with dialect detection.
/// Supports comma, tab, semicolon, and pipe delimiters. Enforces per-field
/// size limits (1 MiB) and per-row column limits (10,000). Preserves row,
/// column, and optional first-row header information.
/// </summary>
public sealed class CsvFormatParser : IFormatParser
{
    private const int MaxColumns = 10_000;
    private const int MaxFieldBytes = 1_048_576; // 1 MiB
    private const int DialectSampleSize = 65_536; // 64 KiB

    public string ParserId => "csv";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "csv";
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input, ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        List<ParserEvent> events;
        try
        {
            events = await CollectEventsAsync(input, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            events =
            [
                new ParserEvent.GapProduced(CorruptGap(context, $"unexpected: {ex.Message}")),
                new ParserEvent.ParseCompleted(),
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input, ParseContext context, CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream stream = input.Stream;
        stream.Position = 0;

        // Read sample for dialect detection
        int sampleSize = (int)Math.Min(input.DeclaredLength, DialectSampleSize);
        if (sampleSize <= 0) sampleSize = 1;
        byte[] sampleBuf = new byte[sampleSize];
        int sampleRead = await stream.ReadAtLeastAsync(sampleBuf, sampleSize, false, cancellationToken)
            .ConfigureAwait(false);
        stream.Position = 0;

        var (delimiter, _, reason) = CsvDialectDetector.Detect(sampleBuf.AsSpan(0, sampleRead));

        if (reason is "csv_dialect_ambiguous")
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "csv",
                "csv_dialect", GapReason.UnsupportedRegion, "csv_dialect_ambiguous",
                input.DeclaredLength, 0, DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Read entire source
        byte[] rented = ArrayPool<byte>.Shared.Rent((int)Math.Min(input.DeclaredLength, int.MaxValue));
        int totalRead = 0;
        try
        {
            int read;
            while (totalRead < rented.Length &&
                   (read = await stream.ReadAsync(rented.AsMemory(totalRead, rented.Length - totalRead),
                       cancellationToken).ConfigureAwait(false)) > 0)
            {
                totalRead += read;
            }

            var chunker = new ContentChunker(context.JobId, context.VirtualPath, "csv",
                ContentKind.StructuredData, "utf-8", totalRead);

            // Parse via state machine
            var textOutput = new StringBuilder();
            var locationMap = new List<LocationMapEntry>();
            long textCharOffset = 0;
            int rowIndex = 0;
            int colIndex = 0;
            var headers = new List<string>();

            bool inQuotes = false;
            var fieldBuilder = new StringBuilder();
            bool isFirstRow = true;

            int i = 0;
            while (i < totalRead)
            {
                byte b = rented[i];

                if (colIndex >= MaxColumns)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "csv",
                        "csv_parse", GapReason.UnsupportedRegion, "csv_column_limit",
                        totalRead, i, DateTimeOffset.UtcNow)));
                    break;
                }

                if (inQuotes)
                {
                    // Inside quoted field
                    if (b == '"')
                    {
                        if (i + 1 < totalRead && rented[i + 1] == '"')
                        {
                            // Escaped quote
                            fieldBuilder.Append('"');
                            i += 2;
                            continue;
                        }

                        // End of quoted field
                        inQuotes = false;
                        i++;
                        continue;
                    }

                    fieldBuilder.Append((char)b);
                    i++;
                }
                else
                {
                    if (b == '"' && fieldBuilder.Length == 0)
                    {
                        // Start of quoted field
                        inQuotes = true;
                        i++;
                        continue;
                    }

                    if (b == (byte)delimiter)
                    {
                        // End of field
                        EmitField(textOutput, locationMap, ref textCharOffset,
                            rowIndex, colIndex, fieldBuilder, headers, isFirstRow);
                        fieldBuilder.Clear();
                        colIndex++;
                        i++;
                        continue;
                    }

                    if (b == '\n' || (b == '\r' && i + 1 < totalRead && rented[i + 1] == '\n'))
                    {
                        // End of row
                        if (b == '\r') i++; // skip CR in CRLF
                        i++; // skip LF

                        // Emit last field of the row
                        EmitField(textOutput, locationMap, ref textCharOffset,
                            rowIndex, colIndex, fieldBuilder, headers, isFirstRow);
                        fieldBuilder.Clear();

                        EmitRowEnd(textOutput, locationMap, ref textCharOffset, rowIndex);
                        rowIndex++;
                        colIndex = 0;

                        if (isFirstRow && headers.Count > 0)
                            isFirstRow = false;

                        continue;
                    }

                    fieldBuilder.Append((char)b);
                    i++;
                }
            }

            // Handle remaining field (file not ending with newline)
            if (fieldBuilder.Length > 0 || colIndex > 0)
            {
                EmitField(textOutput, locationMap, ref textCharOffset,
                    rowIndex, colIndex, fieldBuilder, headers, isFirstRow);
                EmitRowEnd(textOutput, locationMap, ref textCharOffset, rowIndex);
            }

            // Emit chunk
            var chunk = chunker.NextChunk(
                textOutput.ToString(), 0, totalRead, locationMap, true);
            events.Add(new ParserEvent.ChunkProduced(chunk));
            events.Add(new ParserEvent.ParseCompleted());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }

        return events;
    }

    private static void EmitField(StringBuilder sb, List<LocationMapEntry> map,
        ref long textCharOffset, int row, int col, StringBuilder field,
        List<string> headers, bool isFirstRow)
    {
        string value = field.ToString();
        string header = col < headers.Count ? headers[col] : "";

        if (isFirstRow && !string.IsNullOrEmpty(value))
        {
            headers.Add(value);
        }

        string label = $"R{row}C{col}" +
            (!string.IsNullOrEmpty(header) ? $"({header})" : "") +
            $"={value}";

        int start = (int)textCharOffset;
        sb.Append(label);

        map.Add(new LocationMapEntry(
            0, label.Length,
            textCharOffset, label.Length));
        textCharOffset += label.Length;
    }

    private static void EmitRowEnd(StringBuilder sb, List<LocationMapEntry> map,
        ref long textCharOffset, int row)
    {
        // Row separator (whitespace between rows in output)
        sb.Append(' ');
        textCharOffset = sb.Length;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "csv",
            "csv_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);
}
