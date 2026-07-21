using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Core;

/// <summary>
/// Closed hierarchy of events produced during a parse. Every parse yields at
/// least one <see cref="ParseCompleted"/> at termination.
/// </summary>
public abstract record ParserEvent
{
    private ParserEvent() { }

    /// <summary>A content chunk was produced from the source.</summary>
    public sealed record ChunkProduced(ContentChunk Chunk) : ParserEvent;

    /// <summary>
    /// A nested/embedded artifact was discovered and should be parsed
    /// recursively (e.g. a ZIP entry, OLE stream, or JSON sub-document).
    /// </summary>
    public sealed record ChildDiscovered(string VirtualPath, FormatProbe Probe) : ParserEvent;

    /// <summary>
    /// A coverage gap was encountered — a region of the source that could not
    /// be parsed into structured content.
    /// </summary>
    public sealed record GapProduced(CoverageGap Gap) : ParserEvent;

    /// <summary>Terminal event: parsing completed successfully.</summary>
    public sealed record ParseCompleted() : ParserEvent;
}
