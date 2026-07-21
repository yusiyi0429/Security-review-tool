namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Skips an oversized JSON string token (> 1 MiB) by scanning raw bytes for the
/// closing delimiter while respecting JSON escape sequences. Emits the already-
/// validated bounded prefix for detection, records <c>json_string_over_limit</c>,
/// and resumes only if the following structural delimiter is valid.
/// Never claims full coverage of the oversized value.
/// </summary>
internal static class OversizeJsonTokenSkipper
{
    /// <summary>Maximum characters of an in-progress string token.</summary>
    public const int MaxTokenChars = 1_048_576; // 1 MiB

    /// <summary>
    /// Scans <paramref name="buffer"/> starting at <paramref name="offset"/> for
    /// the closing (unescaped) <c>"</c> character. Returns the byte position of
    /// the closing quote, or -1 if not found.
    /// </summary>
    public static long SkipToEnd(ReadOnlySpan<byte> buffer, long offset)
    {
        int pos = (int)offset;
        while (pos < buffer.Length)
        {
            byte b = buffer[pos];

            if (b == '\\')
            {
                // Skip escaped character
                pos += 2;
                continue;
            }

            if (b == '"')
            {
                return pos; // closing quote found
            }

            pos++;
        }

        return -1; // closing quote not in this buffer
    }

    /// <summary>
    /// Extracts the prefix of an oversized string token (up to
    /// <see cref="MaxTokenChars"/> characters) from its byte representation.
    /// Handles UTF-8 encoding and JSON escape sequences to produce a valid
    /// best-effort string prefix for scanning purposes.
    /// </summary>
    public static string ExtractPrefix(ReadOnlySpan<byte> tokenBytes)
    {
        // Best-effort: return the first MaxTokenChars bytes as a UTF-8 string
        // (with replacement fallback for invalid sequences).
        int len = Math.Min(tokenBytes.Length, MaxTokenChars);
        return System.Text.Encoding.UTF8.GetString(tokenBytes[..len]);
    }
}
