using System.Buffers;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Parsers.Text;

/// <summary>
/// Produces <see cref="ContentChunk"/> instances from a decoded text source.
/// Targets 512 KiB UTF-8 text per chunk and carries up to 4,096 bytes of
/// source overlap. Location map entries are clipped to the chunk text window
/// and re-based to chunk-relative text coordinates (capped at 8,192 sorted
/// non-overlapping entries), so the parent's <see cref="ContentChunk.Validate"/>
/// always passes. The chunker never truncates text: protocol frame safety is
/// enforced at send time by <see cref="ContentChunkSplitter"/>, which measures
/// the exact serialized frame and splits oversized chunks. Monotonic sequence
/// numbers, original source byte ranges, and IsFinal are guaranteed.
/// </summary>
public sealed class ContentChunker
{
    private const int TargetTextBytes = 512 * 1024;       // 512 KiB
    private const int OverlapSourceBytes = 4_096;          // 4 KiB source overlap
    private const int MaxLocationMapEntries = ContentChunk.MaxLocationMapEntries; // 8,192

    private readonly JobId _jobId;
    private readonly string _virtualPath;
    private readonly string _formatId;
    private readonly ContentKind _contentKind;
    private readonly string _encodingName;
    private readonly long _sourceLength;

    private long _sequence;
    private long _sourceOffset;

    public ContentChunker(JobId jobId, string virtualPath, string formatId,
        ContentKind contentKind, string encodingName, long sourceLength)
    {
        _jobId = jobId;
        _virtualPath = virtualPath;
        _formatId = formatId;
        _contentKind = contentKind;
        _encodingName = encodingName;
        _sourceLength = sourceLength;
        _sequence = 0;
        _sourceOffset = 0;
    }

    /// <summary>
    /// Produce the next chunk from the given text segment. The text segment
    /// maps to bytes [sourceStart, sourceStart + sourceLength) in the original
    /// source. The locationMap maps source-byte ranges to text-char ranges
    /// relative to <paramref name="text"/> (chunk-relative); callers with
    /// full-file coordinates must re-base first (see <see cref="ChunkAll"/>).
    /// The chunk text is emitted in full — frame-size splitting happens at
    /// send time in <see cref="ContentChunkSplitter"/>.
    /// </summary>
    public ContentChunk NextChunk(string text, long sourceStart, long sourceLength,
        IReadOnlyList<LocationMapEntry> locationMap, bool isFinal)
    {
        if (text.Length == 0 && !isFinal)
            throw new ArgumentException("Non-final chunk must contain text.", nameof(text));

        // Limit location map entries
        var cappedMap = CapLocationMap(locationMap);

        var chunk = new ContentChunk(
            ProtocolVersion: ProtocolConstants.Version,
            JobId: _jobId,
            Sequence: _sequence++,
            VirtualPath: _virtualPath,
            FormatId: _formatId,
            ContentKind: _contentKind,
            Encoding: _encodingName,
            Text: text,
            SourceStart: sourceStart,
            SourceLength: sourceLength,
            LocationMap: cappedMap.ToList(),
            IsFinal: isFinal);

        _sourceOffset = sourceStart + sourceLength;
        return chunk;
    }

    /// <summary>
    /// Split <paramref name="fullText"/> into chunks with overlap. Each chunk
    /// carries text + location map. Long lines split across chunks maintain
    /// continuous column/byte mapping.
    /// </summary>
    public IReadOnlyList<ContentChunk> ChunkAll(string fullText,
        IReadOnlyList<LocationMapEntry> fullLocationMap, long totalSourceLength)
    {
        var chunks = new List<ContentChunk>();

        if (fullText.Length == 0)
        {
            chunks.Add(NextChunk(fullText, 0, totalSourceLength, fullLocationMap, true));
            return chunks;
        }

        int offset = 0;
        int previousEnd = 0;
        while (offset < fullText.Length)
        {
            bool isFinal = false;
            int remaining = fullText.Length - offset;
            int targetLength = Math.Min(remaining, TargetTextBytes / 4); // chars, approx

            // Estimate UTF-8 bytes: assume 1-4 bytes per char, typically ~1.5 for mixed content
            int targetChars = targetLength;

            int end = offset + targetChars;
            if (end >= fullText.Length)
            {
                end = fullText.Length;
                isFinal = true;
            }

            // Don't split in the middle of a surrogate pair
            if (end < fullText.Length && char.IsHighSurrogate(fullText[end - 1]))
            {
                end--;
            }

            string segment = fullText[offset..end];
            long segSourceStart = previousEnd > 0 ? previousEnd - OverlapSourceBytes : 0;
            if (segSourceStart < 0) segSourceStart = 0;
            long segSourceLength = Math.Min(totalSourceLength - segSourceStart,
                (long)Encoding.UTF8.GetByteCount(segment) + OverlapSourceBytes);

            // Build location map for this segment: clip the full-file map to
            // the segment's text window and re-base entries to chunk-relative
            // text coordinates (source coordinates stay absolute).
            var segMap = FilterLocationMap(fullLocationMap, offset, segment.Length);

            chunks.Add(NextChunk(segment, segSourceStart, segSourceLength, segMap, isFinal));

            offset = end;
            // Carry source-overlap characters forward for next chunk's continuity
            int charOverlap = OverlapSourceBytes; // brief: "4,096 bytes/characters of overlap"
            if (end < fullText.Length && offset > charOverlap)
            {
                offset -= charOverlap;
            }
            previousEnd = offset;
        }

        return chunks;
    }

    private static IReadOnlyList<LocationMapEntry> CapLocationMap(
        IReadOnlyList<LocationMapEntry> map)
    {
        if (map.Count <= MaxLocationMapEntries)
            return map;

        // Cap at MaxLocationMapEntries, keeping sorted non-overlapping entries,
        // coalescing adjacent linear runs where entry.SourceStart+SourceLength == next.SourceStart.
        var sorted = map.OrderBy(e => e.SourceStart).ToList();
        var result = new List<LocationMapEntry>(MaxLocationMapEntries);
        long previousEnd = -1;

        foreach (var entry in sorted)
        {
            if (result.Count >= MaxLocationMapEntries)
                break;

            // Skip overlapping entries
            if (entry.SourceStart < previousEnd)
                continue;

            if (previousEnd >= 0 && entry.SourceStart == previousEnd
                && result.Count > 0
                && result[^1].TextStart + result[^1].TextLength == entry.SourceStart)
            {
                // Coalesce adjacent entries: extend the last entry
                var last = result[^1];
                long newSrcLen = last.SourceLength + entry.SourceLength;
                long newTextLen = last.TextLength + entry.TextLength;
                result[^1] = new LocationMapEntry(last.SourceStart, newSrcLen, last.TextStart, newTextLen);
                previousEnd = last.SourceStart + newSrcLen;
            }
            else
            {
                result.Add(entry);
                previousEnd = entry.SourceStart + entry.SourceLength;
            }
        }

        return result;
    }

    /// <summary>
    /// Clip <paramref name="fullMap"/> to the text window
    /// [textWindowStart, textWindowStart + textWindowLength) of the full text
    /// and re-base the surviving entries to window-relative (chunk-relative)
    /// text coordinates via <see cref="ContentChunkSplitter.RebaseLocationMap"/>.
    /// </summary>
    private static IReadOnlyList<LocationMapEntry> FilterLocationMap(
        IReadOnlyList<LocationMapEntry> fullMap, long textWindowStart, long textWindowLength)
    {
        return CapLocationMap(ContentChunkSplitter.RebaseLocationMap(
            fullMap, textWindowStart, textWindowLength));
    }
}
