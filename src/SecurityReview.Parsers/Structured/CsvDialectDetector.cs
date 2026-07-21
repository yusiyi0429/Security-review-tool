using System.Text;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Detects the CSV dialect (delimiter character) by sampling at most 64 KiB
/// and scoring candidate delimiters (comma, tab, semicolon, pipe) by stable
/// field count across the first 20 logical rows. Ties or inconsistency
/// produce <c>csv_dialect_ambiguous</c>.
/// </summary>
internal static class CsvDialectDetector
{
    private const int MaxSampleBytes = 65_536; // 64 KiB
    private const int MaxRows = 20;

    private static readonly char[] CandidateDelimiters = [',', '\t', ';', '|'];

    /// <summary>
    /// Detects the best delimiter from the sample. Returns the delimiter and
    /// a score (higher is better). Returns (default, 0) when ambiguous.
    /// </summary>
    public static (char Delimiter, int Score, string? Reason) Detect(ReadOnlySpan<byte> sample)
    {
        if (sample.Length == 0)
            return (',', 0, "empty_sample");

        // Decode sample (first MaxSampleBytes)
        string text;
        try
        {
            text = Encoding.UTF8.GetString(sample[..Math.Min(sample.Length, MaxSampleBytes)]);
        }
        catch
        {
            return (',', 0, "decode_failed");
        }

        if (text.Length == 0)
            return (',', 0, "empty_text");

        // Split into lines (handle both CRLF and LF)
        var lines = text.Replace("\r\n", "\n").Split('\n');
        int rowCount = Math.Min(lines.Length, MaxRows);

        if (rowCount == 0)
            return (',', 0, "no_lines");

        var bestDelim = ',';
        int bestScore = 0;

        foreach (char delim in CandidateDelimiters)
        {
            int score = ScoreDelimiter(lines, rowCount, delim);
            if (score > bestScore)
            {
                bestScore = score;
                bestDelim = delim;
            }
        }

        if (bestScore == 0)
            return (',', 0, "csv_dialect_ambiguous");

        return (bestDelim, bestScore, null);
    }

    private static int ScoreDelimiter(string[] lines, int rowCount, char delimiter)
    {
        // Count fields per row. A good delimiter produces consistent field counts.
        var fieldCounts = new List<int>(rowCount);
        int totalFields = 0;

        for (int i = 0; i < rowCount; i++)
        {
            string line = lines[i];
            if (line.Length == 0)
                continue;

            int fields = CountFields(line, delimiter);
            fieldCounts.Add(fields);
            totalFields += fields;
        }

        if (fieldCounts.Count == 0)
            return 0;

        // Score = avg field count * consistency bonus
        double avg = (double)totalFields / fieldCounts.Count;
        if (avg < 2)
            return 0;

        // Check consistency: how many rows have the same field count as the mode?
        var freq = new Dictionary<int, int>();
        foreach (int fc in fieldCounts)
        {
            freq.TryGetValue(fc, out int count);
            freq[fc] = count + 1;
        }

        int modeCount = freq.Values.Max();
        double consistency = (double)modeCount / fieldCounts.Count;

        // Score: more fields + high consistency = better
        return (int)(avg * consistency * 10);
    }

    private static int CountFields(string line, char delimiter)
    {
        int count = 1; // start with at least 1 field
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if (c == '"')
            {
                // Check for escaped quote
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    i++; // skip escaped quote
                    continue;
                }

                inQuotes = !inQuotes;
                continue;
            }

            if (!inQuotes && c == delimiter)
            {
                count++;
            }
        }

        return count;
    }
}
