namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Escape-proof virtual path used exclusively for intra-parse routing.
/// Never touches the filesystem. Builds composite paths with the
/// <c>outer!/inner</c> separator so the worker can distinguish archive
/// hierarchies from physical directory nesting.
/// </summary>
public static class VirtualPath
{
    /// <summary>
    /// Maximum length in UTF-16 code units for a composed virtual path.
    /// </summary>
    public const int MaxPathLength = 4_096;

    /// <summary>
    /// Renders a sanitized virtual child path.
    /// </summary>
    /// <param name="entryName">Raw entry name from the archive header.</param>
    /// <param name="parentPath">Current virtual path of the parent job (e.g.
    /// <c>"project/docs.zip"</c>).</param>
    /// <param name="entryIndex">Zero-based entry ordinal for diagnostic reporting.</param>
    /// <returns>The composed <c>outer!/inner</c> path.</returns>
    /// <exception cref="ArgumentException">The entry name is empty, contains NUL,
    /// unpaired surrogate code points, drive/UNC/absolute root markers,
    /// parent-reference segments, or percent-encoded escape sequences.</exception>
    /// <exception cref="FormatException">The composed path exceeds
    /// <see cref="MaxPathLength"/> UTF-16 code units.</exception>
    public static string ParseEntry(string entryName, string parentPath, int entryIndex)
    {
        ArgumentNullException.ThrowIfNull(entryName);
        ArgumentNullException.ThrowIfNull(parentPath);
        ArgumentOutOfRangeException.ThrowIfNegative(entryIndex);

        // --- step 1: reject empty ---
        if (entryName.Length == 0)
            throw new ArgumentException("Entry name must not be empty.", nameof(entryName));

        // --- step 2: reject NUL ---
        if (entryName.Contains('\0', StringComparison.Ordinal))
            throw new ArgumentException("Entry name contains NUL byte.", nameof(entryName));

        // --- step 3: reject surrogates ---
        if (!IsWellFormedUnicode(entryName))
            throw new ArgumentException("Entry name contains unpaired surrogate.", nameof(entryName));

        // --- step 4: normalize separators (/ and \) to / ---
        string sanitized = entryName.Replace('\\', '/');

        // --- step 5: reject percent-encoded escapes ---
        if (sanitized.Contains('%'))
            throw new ArgumentException("Entry name contains percent-encoded sequence.", nameof(entryName));

        // --- step 6: per-segment checks ---
        Span<Range> segmentRanges = stackalloc Range[256]; // worst-case: each char is a separator
        int segmentCount = SplitPathSegments(sanitized, segmentRanges);

        if (segmentCount == 0)
            segmentRanges[0] = new Range(0, sanitized.Length);
        if (segmentCount > 0)
        {
            // Re-split since span may be on too-small for long paths
            string[] segments = sanitized.Split('/');
            segmentCount = segments.Length;

            foreach (string segment in segments)
            {
                if (segment.Length == 0)
                {
                    // Two adjacent slashes or leading/trailing slash
                    throw new ArgumentException(
                        $"Entry name contains empty path segment (absolute or double-separator).",
                        nameof(entryName));
                }

                if (segment == ".")
                    throw new ArgumentException(
                        $"Entry name contains current-directory segment '.'.", nameof(entryName));

                if (segment == "..")
                    throw new ArgumentException(
                        $"Entry name contains parent-reference segment '..'.", nameof(entryName));

                // Reject drive letters: e.g., "C:" as a segment
                if (segment.Length >= 2 && char.IsAsciiLetter(segment[0]) && segment[1] == ':')
                    throw new ArgumentException(
                        $"Entry name contains drive letter segment.", nameof(entryName));

                // UNC: starts with two backslashes — but we already normalized
                // to forward slashes, so a segment like "\\server" would have been
                // split; check for UNC-style leading double slash (caught above
                // by empty-segment check after split). Additional check: a segment
                // that looks like a UNC host (starts with //) is impossible after
                // normalization unless the raw input had "//" — which would mean
                // path starts with // (empty first segment caught above).
            }
        }

        // --- step 7: special check for drive-letter prefix at root (e.g. "C:/foo") ---
        if (sanitized.Length >= 2 && char.IsAsciiLetter(sanitized[0]) && sanitized[1] == ':')
            throw new ArgumentException("Entry name contains drive letter prefix.", nameof(entryName));

        // --- step 8: compose ---
        string composed = string.Concat(parentPath, "!/", sanitized);

        if (composed.Length > MaxPathLength)
            throw new FormatException($"Virtual path exceeds {MaxPathLength} UTF-16 code units.");

        return composed;
    }

    /// <summary>
    /// Computes the display-name portion of the virtual path (the last <c>!/</c>
    /// segment or the full path when no separator exists).
    /// </summary>
    public static string DisplayName(string virtualPath)
    {
        int sep = virtualPath.LastIndexOf("!/", StringComparison.Ordinal);
        return sep >= 0 ? virtualPath[(sep + 2)..] : virtualPath;
    }

    internal static bool IsWellFormedUnicode(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(value[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static int SplitPathSegments(ReadOnlySpan<char> path, Span<Range> ranges)
    {
        int count = 0;
        int start = 0;
        for (int i = 0; i < path.Length; i++)
        {
            if (path[i] == '/')
            {
                if (i > start)
                {
                    if (count < ranges.Length)
                        ranges[count] = new Range(start, i);
                    count++;
                }
                start = i + 1;
            }
        }

        if (start < path.Length)
        {
            if (count < ranges.Length)
                ranges[count] = new Range(start, path.Length);
            count++;
        }

        return count;
    }
}
