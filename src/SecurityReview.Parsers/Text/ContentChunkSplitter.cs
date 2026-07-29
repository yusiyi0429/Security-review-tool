using System.Text;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Parsers.Text;

/// <summary>
/// Splits a <see cref="ContentChunk"/> whose serialized protocol frame would
/// exceed the IPC frame limit into ordered pieces that each fit. The worker
/// double-serializes each chunk (chunk JSON embedded as a string inside the
/// protocol envelope), so CJK text (<c>\\uXXXX</c>, 6 bytes per char) and
/// escape-dense content can inflate a 128 KiB chunk past
/// <see cref="ProtocolConstants.MaxFrameBytes"/> and crash the worker.
/// Splitting preserves the mapping invariants: text is halved at a Unicode
/// scalar boundary, source ranges advance by exact UTF-8 byte counts,
/// location map entries are clipped and re-based per piece, and IsFinal is
/// carried only by the last piece. JobId, Sequence, VirtualPath, FormatId,
/// ContentKind, and Encoding are preserved on every piece.
/// </summary>
public static class ContentChunkSplitter
{
    /// <summary>
    /// Safety threshold for a single chunk frame: 80% of
    /// <see cref="ProtocolConstants.MaxFrameBytes"/> (1 MiB). The 20% headroom
    /// absorbs envelope metadata variance (sequence digit count between the
    /// measurement and the actual send, correlation IDs) without changing the
    /// wire format.
    /// </summary>
    public const int MaxChunkFrameBytes = ProtocolConstants.MaxFrameBytes * 4 / 5; // 838,860

    /// <summary>
    /// Returns <paramref name="chunk"/> as a single-element list when its
    /// serialized frame fits under <see cref="MaxChunkFrameBytes"/>; otherwise
    /// recursively halves it until every piece fits, preserving order.
    /// <paramref name="measureFrameBytes"/> must measure the exact frame the
    /// caller will send (chunk payload double-serialized inside the protocol
    /// envelope). Returns null when even a minimal piece cannot fit — the
    /// caller should report a controlled gap instead of sending.
    /// </summary>
    public static IReadOnlyList<ContentChunk>? SplitForFrame(
        ContentChunk chunk, Func<ContentChunk, int> measureFrameBytes)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        ArgumentNullException.ThrowIfNull(measureFrameBytes);

        var pieces = new List<ContentChunk>();
        return TrySplit(chunk, measureFrameBytes, pieces) ? pieces : null;
    }

    /// <summary>
    /// Clips <paramref name="map"/> to the text window
    /// [textWindowStart, textWindowStart + textWindowLength) of the original
    /// chunk text and re-bases the surviving entries to window-relative text
    /// coordinates (<c>TextStart -= textWindowStart</c>). Source coordinates
    /// stay absolute; entries crossing a window edge are clipped with linear
    /// interpolation inside the entry, the same assumption detectors already
    /// make when consuming the map. Entries are assumed sorted by TextStart;
    /// entries overlapping the previous kept entry in text are dropped, and
    /// entries whose source range overlaps the previous kept entry are dropped
    /// as well (first one wins), so the result always satisfies the parent's
    /// sorted/non-overlapping source invariant in <see cref="ContentChunk.Validate"/>
    /// even for pathological maps with disjoint text but overlapping source
    /// ranges. Shared with the ContentChunker location-map filtering path.
    /// </summary>
    public static IReadOnlyList<LocationMapEntry> RebaseLocationMap(
        IReadOnlyList<LocationMapEntry> map,
        long textWindowStart,
        long textWindowLength)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentOutOfRangeException.ThrowIfNegative(textWindowStart);
        ArgumentOutOfRangeException.ThrowIfNegative(textWindowLength);

        long textWindowEnd = textWindowStart + textWindowLength;
        var rebased = new List<LocationMapEntry>();
        long previousTextEnd = textWindowStart;
        long previousSourceEnd = 0;

        foreach (LocationMapEntry entry in map)
        {
            if (entry.TextLength == 0)
            {
                // Source-only anchor: keep it when its position falls inside
                // the window, with source coordinates unchanged.
                if (entry.TextStart < textWindowStart || entry.TextStart >= textWindowEnd)
                    continue;
                if (entry.SourceStart < previousSourceEnd)
                    continue; // source overlap; the parent's Validate would fail

                rebased.Add(new LocationMapEntry(entry.SourceStart, entry.SourceLength,
                    entry.TextStart - textWindowStart, 0));
                previousTextEnd = entry.TextStart;
                previousSourceEnd = entry.SourceStart;
                continue;
            }

            long entryTextEnd = entry.TextStart + entry.TextLength;
            if (entry.TextStart >= textWindowEnd || entryTextEnd <= textWindowStart)
                continue;

            long clipStart = Math.Max(entry.TextStart, textWindowStart);
            long clipEnd = Math.Min(entryTextEnd, textWindowEnd);
            if (clipStart < previousTextEnd)
                continue; // overlaps the previous kept entry; drop it

            long clipLength = clipEnd - clipStart;
            long sourceStart = entry.SourceStart
                + (clipStart - entry.TextStart) * entry.SourceLength / entry.TextLength;
            long sourceLength = clipLength * entry.SourceLength / entry.TextLength;
            if (sourceStart < previousSourceEnd)
                continue; // pathological map: disjoint text but overlapping
                          // source; keep the first so Validate stays clean

            rebased.Add(new LocationMapEntry(sourceStart, sourceLength,
                clipStart - textWindowStart, clipLength));
            previousTextEnd = clipEnd;
            previousSourceEnd = sourceStart + sourceLength;
        }

        return rebased;
    }

    private static bool TrySplit(
        ContentChunk chunk, Func<ContentChunk, int> measureFrameBytes,
        List<ContentChunk> pieces)
    {
        if (measureFrameBytes(chunk) <= MaxChunkFrameBytes)
        {
            pieces.Add(chunk);
            return true;
        }

        string text = chunk.Text;
        if (text.Length <= 1)
        {
            // A minimal chunk still exceeds the threshold (metadata/location
            // map bound). Theoretically unreachable; the caller reports a gap.
            return false;
        }

        // Halve at a Unicode scalar boundary (never inside a surrogate pair).
        int splitAt = text.Length / 2;
        if (char.IsHighSurrogate(text[splitAt - 1]))
            splitAt--;
        if (splitAt <= 0)
            return false; // lone surrogate pair; cannot split further

        string headText = text[..splitAt];
        string tailText = text[splitAt..];

        // Advance the source window by the exact UTF-8 byte count of the head.
        long headSourceLength = Math.Min(
            Encoding.UTF8.GetByteCount(headText), chunk.SourceLength);

        var head = chunk with
        {
            Text = headText,
            SourceLength = headSourceLength,
            LocationMap = RebaseLocationMap(chunk.LocationMap, 0, headText.Length),
            IsFinal = false,
        };
        var tail = chunk with
        {
            Text = tailText,
            SourceStart = chunk.SourceStart + headSourceLength,
            SourceLength = chunk.SourceLength - headSourceLength,
            LocationMap = RebaseLocationMap(chunk.LocationMap, splitAt, tailText.Length),
        };

        return TrySplit(head, measureFrameBytes, pieces)
            && TrySplit(tail, measureFrameBytes, pieces);
    }
}
