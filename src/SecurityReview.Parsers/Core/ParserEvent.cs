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
    /// <summary>
    /// A nested/embedded artifact was discovered and should be parsed
    /// recursively (e.g. a ZIP entry, OLE stream, or JSON sub-document).
    /// </summary>
    /// <param name="VirtualPath">Virtual routing path (e.g. <c>"outer.zip!/inner.txt"</c>).</param>
    /// <param name="Probe">Format probe of the child stream head/tail.</param>
    /// <param name="StreamFactory">
    /// Factory that opens a fresh seekable <see cref="Stream"/> over the child
    /// content. The factory is valid only while the parent parse job is alive;
    /// calling it after the parent <see cref="ParserInput"/> has been disposed
    /// is undefined. <c>null</c> when the child is metadata-only (e.g. symlinks).
    /// </param>
    public sealed record ChildDiscovered(
        string VirtualPath,
        FormatProbe Probe,
        Func<CancellationToken, Task<Stream>>? StreamFactory = null) : ParserEvent;

    /// <summary>
    /// A coverage gap was encountered — a region of the source that could not
    /// be parsed into structured content.
    /// </summary>
    public sealed record GapProduced(CoverageGap Gap) : ParserEvent;

    /// <summary>Terminal event: parsing completed successfully.</summary>
    public sealed record ParseCompleted() : ParserEvent;
}
