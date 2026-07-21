using System.Buffers;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Parsers.Text;

/// <summary>
/// Produces <see cref="ContentChunk"/> instances from a decoded text source.
/// Targets 512 KiB UTF-8 text per chunk, carries up to 4,096 bytes of source
/// overlap, and ensures the full protocol envelope fits within 1 MiB
/// (<see cref="ProtocolConstants.MaxFrameBytes"/>). Location maps are capped
/// at 8,192 sorted non-overlapping entries; the chunk is shrunk before any
/// entry is dropped. Monotonic sequence numbers, original source byte ranges,
/// and IsFinal are guaranteed.
/// </summary>
public sealed class ContentChunker
{
    private const int TargetTextBytes = 512 * 1024;       // 512 KiB
    private const int OverlapSourceBytes = 4_096;          // 4 KiB source overlap
    private const int MaxEnvelopeBytes = ProtocolConstants.MaxFrameBytes; // 1 MiB
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
    /// source. The locationMap maps source-byte ranges to text-char ranges.
    /// </summary>
    public ContentChunk NextChunk(string text, long sourceStart, long sourceLength,
        IReadOnlyList<LocationMapEntry> locationMap, bool isFinal)
    {
        if (text.Length == 0 && !isFinal)
            throw new ArgumentException("Non-final chunk must contain text.", nameof(text));

        // Limit location map entries
        var cappedMap = CapLocationMap(locationMap);

        // Measure envelope size and shrink if needed
        (string finalText, var finalMap) = FitEnvelope(text, cappedMap, sourceStart, sourceLength);

        var chunk = new ContentChunk(
            ProtocolVersion: ProtocolConstants.Version,
            JobId: _jobId,
            Sequence: _sequence++,
            VirtualPath: _virtualPath,
            FormatId: _formatId,
            ContentKind: _contentKind,
            Encoding: _encodingName,
            Text: finalText,
            SourceStart: sourceStart,
            SourceLength: sourceLength,
            LocationMap: finalMap.ToList(),
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

            // Build location map for this segment
            var segMap = FilterLocationMap(fullLocationMap, segSourceStart, segSourceLength);

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

    private static (string Text, IReadOnlyList<LocationMapEntry> Map) FitEnvelope(
        string text, IReadOnlyList<LocationMapEntry> map,
        long sourceStart, long sourceLength)
    {
        // Estimate the complete envelope size: JSON escaping can roughly 2x text,
        // plus metadata overhead (~512 bytes) and location map serialization.
        // We need the total under MaxEnvelopeBytes.

        int estimatedSize = EstimateEnvelopeSize(text, map);
        if (estimatedSize <= MaxEnvelopeBytes)
            return (text, map);

        // Shrink text at a Unicode scalar boundary until the frame fits
        var shrunkText = text;
        var shrunkMap = map;

        while (estimatedSize > MaxEnvelopeBytes && shrunkText.Length > 0)
        {
            int shrinkTo = (int)((long)shrunkText.Length * MaxEnvelopeBytes / estimatedSize);
            // Round down to Unicode scalar boundary
            shrinkTo = FindScalarBoundary(shrunkText, shrinkTo);
            if (shrinkTo <= 0) shrinkTo = 1;

            shrunkText = shrunkText[..shrinkTo];
            shrunkMap = FilterLocationMap(map, 0, shrunkText.Length);
            estimatedSize = EstimateEnvelopeSize(shrunkText, shrunkMap);
        }

        return (shrunkText, shrunkMap);
    }

    private static int EstimateEnvelopeSize(string text, IReadOnlyList<LocationMapEntry> map)
    {
        // Worst-case estimate: text might be all non-ASCII (3-4 bytes UTF-8),
        // plus JSON escaping (backslash before special chars could roughly 2x).
        // Location map entries: ~50 bytes each when serialized.
        int textEstimate = Encoding.UTF8.GetByteCount(text) * 2; // JSON escaping headroom
        int mapEstimate = map.Count * 60; // generous per-entry estimate
        int overhead = 1024; // envelope metadata

        return textEstimate + mapEstimate + overhead;
    }

    private static int FindScalarBoundary(string text, int position)
    {
        if (position <= 0) return 0;
        if (position >= text.Length) return text.Length;

        // Walk back to find a non-surrogate boundary
        while (position > 0 && char.IsLowSurrogate(text[position]))
            position--;

        return position;
    }

    private static IReadOnlyList<LocationMapEntry> FilterLocationMap(
        IReadOnlyList<LocationMapEntry> fullMap, long sourceStart, long sourceLength)
    {
        long sourceEnd = sourceStart + sourceLength;
        var filtered = new List<LocationMapEntry>();

        foreach (var entry in fullMap)
        {
            long entryEnd = entry.SourceStart + entry.SourceLength;
            // Include entries that overlap with the window
            if (entry.SourceStart < sourceEnd && entryEnd > sourceStart)
            {
                filtered.Add(entry);
            }
        }

        return CapLocationMap(filtered);
    }
}
