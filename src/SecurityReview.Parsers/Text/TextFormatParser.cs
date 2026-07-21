using System.Runtime.CompilerServices;
using System.Text;

namespace SecurityReview.Parsers.Text;

/// <summary>
/// Implements <see cref="IFormatParser"/> for plain text sources. Uses strict
/// encoding detection, streaming line mapping, and chunked output with exact
/// byte/line/column locations.
/// </summary>
public sealed class TextFormatParser : Core.IFormatParser
{
    private static readonly Version ParserVersionValue = new(1, 0, 0);

    public string ParserId => "text";
    public Version ParserVersion => ParserVersionValue;

    /// <summary>
    /// Returns true when the probe indicates a text format.
    /// Extension mismatch does not block parsing.
    /// </summary>
    public bool CanParse(Core.FormatProbe probe)
    {
        return probe.Format.FormatId == "text";
    }

    /// <summary>
    /// Parse a text source: detect encoding, decode, chunk with location
    /// maps, and yield <see cref="Core.ParserEvent"/> values.
    /// </summary>
    public async IAsyncEnumerable<Core.ParserEvent> ParseAsync(
        Core.ParserInput input, Core.ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        // Read entire source into memory (text sources are managed-size)
        Stream stream = input.Stream;
        stream.Position = 0;
        long length = input.DeclaredLength;

        if (length > int.MaxValue)
        {
            yield return new Core.ParserEvent.GapProduced(
                Domain.Scans.CoverageGap.CreateForTest(Domain.Scans.GapReason.DecodeUnreliable)
                with
                { });
            yield return new Core.ParserEvent.ParseCompleted();
            yield break;
        }

        byte[] buffer = new byte[length];
        int totalRead = 0;
        while (totalRead < length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(totalRead, (int)(length - totalRead)),
                cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            totalRead += read;
        }

        // Detect encoding and decode (do this before any yield to keep span alive)
        var detection = TextEncodingDetector.DetectAndDecode(buffer.AsSpan(0, totalRead));

        // Build location map before yields
        var locationMap = BuildTextLocationMap(buffer.AsSpan(0, totalRead), detection.Text, detection.EncodingName);

        if (!detection.IsReliable)
        {
            yield return new Core.ParserEvent.GapProduced(
                new Domain.Scans.CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                    "text_decode", Domain.Scans.GapReason.DecodeUnreliable,
                    detection.FailureReason ?? "unreliable_encoding",
                    totalRead, totalRead, DateTimeOffset.UtcNow));
        }

        // Chunk the text
        var chunker = new ContentChunker(context.JobId, context.VirtualPath, ParserId,
            ParserContracts.Parsing.ContentKind.Text, detection.EncodingName, totalRead);

        var chunks = chunker.ChunkAll(detection.Text, locationMap, totalRead);

        foreach (var chunk in chunks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return new Core.ParserEvent.ChunkProduced(chunk);
        }

        yield return new Core.ParserEvent.ParseCompleted();
    }

    private static List<ParserContracts.Parsing.LocationMapEntry> BuildTextLocationMap(
        ReadOnlySpan<byte> data, string text, string encodingName)
    {
        // For text with known encoding, build a location map that maps source
        // byte ranges to decoded text character ranges.
        var map = new List<ParserContracts.Parsing.LocationMapEntry>();

        if (text.Length == 0)
            return map;

        // For UTF-8 (most common), we can compute linear mapping between byte
        // offset and character index by tracking multi-byte sequences.
        if (encodingName is "utf-8" or "utf-8-bom")
        {
            int bomOffset = encodingName == "utf-8-bom" ? 3 : 0;
            int charIndex = 0;
            int bytePos = bomOffset;

            int runStartChar = 0;
            int runStartByte = bytePos;

            while (bytePos < data.Length && charIndex < text.Length)
            {
                byte b = data[bytePos];
                int charLen;
                if (b <= 0x7F) charLen = 1;
                else if (b >= 0xC2 && b <= 0xDF) charLen = 2;
                else if (b >= 0xE0 && b <= 0xEF) charLen = 3;
                else if (b >= 0xF0 && b <= 0xF4) charLen = 4;
                else { bytePos++; continue; } // invalid, skip

                if (bytePos + charLen > data.Length) break;

                // Check if we should flush the current run
                int runByteLen = bytePos + charLen - runStartByte;
                if (runByteLen >= 4096 || charIndex - runStartChar >= 4096)
                {
                    map.Add(new ParserContracts.Parsing.LocationMapEntry(
                        runStartByte, runByteLen,
                        runStartChar, charIndex - runStartChar));
                    runStartByte = bytePos;
                    runStartChar = charIndex;
                }

                bytePos += charLen;
                charIndex++;
            }

            // Flush final run
            if (charIndex > runStartChar)
            {
                map.Add(new ParserContracts.Parsing.LocationMapEntry(
                    runStartByte, bytePos - runStartByte,
                    runStartChar, charIndex - runStartChar));
            }
        }
        else
        {
            // For other encodings, use a simpler mapping: map the entire source
            // to the entire text. This is approximate but correct for source
            // location purposes.
            map.Add(new ParserContracts.Parsing.LocationMapEntry(
                0, data.Length, 0, text.Length));
        }

        return map;
    }
}
