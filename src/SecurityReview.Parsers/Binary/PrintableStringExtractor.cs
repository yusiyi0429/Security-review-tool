using System.Text;

namespace SecurityReview.Parsers.Binary;

/// <summary>
/// Fallback extractor for printable ASCII and UTF-16 strings from binary
/// content. Scans fixed 1 MiB windows for runs of ≥6 printable characters,
/// preserves byte offsets, and emits explicit generic-binary coverage gaps
/// for all other bytes. This is a fallback only — never evidence that a binary
/// is fully covered.
/// </summary>
public static class PrintableStringExtractor
{
    private const int WindowSize = 1_048_576;          // 1 MiB
    private const int MinRunLength = 6;                 // minimum chars for a run
    private const int MaxRunLength = 1_048_576;         // 1 MiB cap per run
    private const int WindowOverlap = 16;               // 16-byte overlap between windows
    private const int MaxResults = 10_000;              // safety cap

    /// <summary>
    /// A single extracted printable string with its byte range.
    /// </summary>
    public readonly record struct PrintableString(
        string Text,
        long ByteOffset,
        int ByteLength,
        string Encoding)
    {
        public bool IsAscii => Encoding == "ascii";
        public bool IsUtf16LE => Encoding == "utf-16le";
        public bool IsUtf16BE => Encoding == "utf-16be";
    }

    /// <summary>
    /// Result of scanning a binary segment.
    /// </summary>
    public sealed record ExtractionResult(
        IReadOnlyList<PrintableString> Strings,
        IReadOnlyList<(long Offset, long Length)> CoverageGaps,
        long TotalBytesScanned)
    {
        public static ExtractionResult Empty(long totalBytes) =>
            new([], [(0, totalBytes)], totalBytes);
    }

    /// <summary>
    /// Extract printable strings from <paramref name="data"/>. Returns strings
    /// with exact byte offsets plus coverage gaps for bytes not covered.
    /// </summary>
    public static ExtractionResult Extract(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return ExtractionResult.Empty(0);

        var strings = new List<PrintableString>();
        var gaps = new List<(long Offset, long Length)>();

        long offset = 0;
        while (offset < data.Length && strings.Count < MaxResults)
        {
            int windowLen = (int)Math.Min(data.Length - offset, (long)WindowSize);
            ReadOnlySpan<byte> window = data.Slice((int)offset, windowLen);

            ExtractFromWindow(window, (int)offset, strings);

            // Advance with overlap
            offset += windowLen;
            if (offset < data.Length)
                offset -= WindowOverlap;
        }

        // Compute coverage gaps
        ComputeCoverageGaps(strings, data.Length, gaps);

        return new ExtractionResult(strings.AsReadOnly(), gaps.AsReadOnly(), data.Length);
    }

    private static void ExtractFromWindow(ReadOnlySpan<byte> window, long baseOffset,
        List<PrintableString> results)
    {
        int i = 0;
        while (i < window.Length && results.Count < MaxResults)
        {
            // Collect candidates at this position
            var candidates = new List<(int Start, int Length, string Encoding)>();

            // Try ASCII
            (int asciiStart, int asciiLen) = FindAsciiRun(window, i);
            if (asciiLen >= MinRunLength)
                candidates.Add((asciiStart, Math.Min(asciiLen, MaxRunLength), "ascii"));

            // Try UTF-16LE (even-byte-aligned)
            int alignedStart = (i + 1) & ~1;
            if (alignedStart < window.Length - 1)
            {
                (int leStart, int leLen) = FindUtf16LeRun(window, alignedStart);
                if (leLen >= MinRunLength * 2)
                    candidates.Add((leStart, Math.Min(leLen, MaxRunLength * 2) & ~1, "utf-16le"));
            }

            // Try UTF-16BE (even-byte-aligned)
            if (alignedStart < window.Length - 1)
            {
                (int beStart, int beLen) = FindUtf16BeRun(window, alignedStart);
                if (beLen >= MinRunLength * 2)
                    candidates.Add((beStart, Math.Min(beLen, MaxRunLength * 2) & ~1, "utf-16be"));
            }

            // Pick best candidate: prefer most ASCII chars in decoded text,
            // then longer run
            if (candidates.Count > 0)
            {
                (int Start, int Length, string Encoding) best = candidates[0];
                int bestScore = ScoreCandidate(window, best);
                for (int ci = 1; ci < candidates.Count; ci++)
                {
                    var c = candidates[ci];
                    int score = ScoreCandidate(window, c);
                    if (score > bestScore || (score == bestScore && c.Length > best.Length))
                    {
                        best = c;
                        bestScore = score;
                    }
                }

                string text = best.Encoding switch
                {
                    "ascii" => Encoding.ASCII.GetString(window.Slice(best.Start, best.Length)),
                    "utf-16le" => Encoding.Unicode.GetString(window.Slice(best.Start, best.Length)),
                    "utf-16be" => Encoding.BigEndianUnicode.GetString(window.Slice(best.Start, best.Length)),
                    _ => string.Empty
                };

                results.Add(new PrintableString(text, baseOffset + best.Start, best.Length, best.Encoding));
                i = best.Start + best.Length;
            }
            else
            {
                i++;
            }
        }
    }

    private static (int Start, int Length) FindAsciiRun(ReadOnlySpan<byte> data, int start)
    {
        int runStart = -1;
        int runLen = 0;
        int maxStart = -1;
        int maxLen = 0;

        for (int i = start; i < data.Length; i++)
        {
            byte b = data[i];
            if (b is >= 0x20 and <= 0x7E)
            {
                if (runStart < 0) runStart = i;
                runLen++;
            }
            else
            {
                if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }
                runStart = -1;
                runLen = 0;
                if (i - start > MaxRunLength) break;
            }
        }

        if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }

        return maxLen >= MinRunLength ? (maxStart, maxLen) : (start, 0);
    }

    private static (int Start, int Length) FindUtf16LeRun(ReadOnlySpan<byte> data, int start)
    {
        int runStart = -1;
        int runLen = 0; // in bytes
        int maxStart = -1;
        int maxLen = 0;

        int limit = Math.Min(data.Length, start + MaxRunLength * 2);

        for (int i = start; i < limit - 1; i += 2)
        {
            ushort ch = (ushort)(data[i] | (data[i + 1] << 8));
            if (IsPrintableUtf16(ch))
            {
                if (runStart < 0) runStart = i;
                runLen += 2;
            }
            else
            {
                if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }
                runStart = -1;
                runLen = 0;
            }
        }

        if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }

        return maxLen >= MinRunLength * 2 ? (maxStart, maxLen) : (start, 0);
    }

    private static (int Start, int Length) FindUtf16BeRun(ReadOnlySpan<byte> data, int start)
    {
        int runStart = -1;
        int runLen = 0;
        int maxStart = -1;
        int maxLen = 0;

        int limit = Math.Min(data.Length, start + MaxRunLength * 2);

        for (int i = start; i < limit - 1; i += 2)
        {
            ushort ch = (ushort)((data[i] << 8) | data[i + 1]);
            if (IsPrintableUtf16(ch))
            {
                if (runStart < 0) runStart = i;
                runLen += 2;
            }
            else
            {
                if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }
                runStart = -1;
                runLen = 0;
            }
        }

        if (runLen > maxLen) { maxStart = runStart; maxLen = runLen; }

        return maxLen >= MinRunLength * 2 ? (maxStart, maxLen) : (start, 0);
    }

    private static bool IsPrintableUtf16(ushort ch)
    {
        if (ch is >= 0x20 and <= 0x7E) return true;     // ASCII printable
        if (ch is >= 0xA0 and <= 0xFF) return true;     // Latin-1 supplement
        if (ch is >= 0x4E00 and <= 0x9FFF) return true; // CJK Unified
        if (ch is >= 0x3000 and <= 0x303F) return true; // CJK punctuation
        if (ch is >= 0xFF00 and <= 0xFFEF) return true; // Half/full-width forms
        if (ch is >= 0x0100 and <= 0x024F) return true; // Latin Extended
        return false;
    }

    private static int ScoreCandidate(ReadOnlySpan<byte> window,
        (int Start, int Length, string Encoding) candidate)
    {
        // Score: count of ASCII printable chars in decoded text.
        // Higher ASCII count = better quality candidate.
        return candidate.Encoding switch
        {
            "ascii" => candidate.Length,
            "utf-16le" => CountAsciiInUtf16(window.Slice(candidate.Start, candidate.Length), false),
            "utf-16be" => CountAsciiInUtf16(window.Slice(candidate.Start, candidate.Length), true),
            _ => 0
        };
    }

    private static int CountAsciiInUtf16(ReadOnlySpan<byte> data, bool bigEndian)
    {
        int count = 0;
        for (int i = 0; i < data.Length - 1; i += 2)
        {
            ushort ch = bigEndian
                ? (ushort)((data[i] << 8) | data[i + 1])
                : (ushort)(data[i] | (data[i + 1] << 8));
            if (ch is >= 0x20 and <= 0x7E) count++;
        }
        return count;
    }

    private static void ComputeCoverageGaps(List<PrintableString> strings, long totalBytes,
        List<(long Offset, long Length)> gaps)
    {
        if (strings.Count == 0)
        {
            gaps.Add((0, totalBytes));
            return;
        }

        // Sort by offset
        strings.Sort((a, b) => a.ByteOffset.CompareTo(b.ByteOffset));

        long covered = 0;
        long gapStart = 0;

        foreach (var s in strings)
        {
            if (s.ByteOffset > gapStart)
            {
                gaps.Add((gapStart, s.ByteOffset - gapStart));
            }

            long sEnd = s.ByteOffset + s.ByteLength;
            if (sEnd > covered) covered = sEnd;
            gapStart = Math.Max(gapStart, sEnd);
        }

        // Gap at end
        if (gapStart < totalBytes)
        {
            gaps.Add((gapStart, totalBytes - gapStart));
        }
    }
}
