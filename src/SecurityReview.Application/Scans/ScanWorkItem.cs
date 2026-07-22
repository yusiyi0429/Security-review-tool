using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Application.Scans;

/// <summary>A unit of work dispatched to the parser worker pool.</summary>
public sealed record ScanWorkItem(
    JobId JobId,
    ScanId ScanId,
    FileId FileId,
    string VirtualPath,
    string FormatHint,
    long DeclaredLength,
    ParseLimits Limits,
    bool IsOci,
    string? InputFilePath = null);

/// <summary>
/// Result produced by a parser worker for a single <see cref="ScanWorkItem"/>.
/// </summary>
public enum WorkerResultKind
{
    /// <summary>A content chunk was produced.</summary>
    Chunk,

    /// <summary>A nested child artifact was discovered.</summary>
    ChildDiscovered,

    /// <summary>A coverage gap was reported.</summary>
    Gap,

    /// <summary>The job completed successfully.</summary>
    Completed,

    /// <summary>The job failed.</summary>
    Failed,

    /// <summary>The job was cancelled.</summary>
    Cancelled,
}

/// <summary>Result of a single worker job execution.</summary>
public sealed record WorkerJobResult(
    JobId JobId,
    FileId FileId,
    WorkerResultKind Kind,
    ContentChunk? Chunk,
    CoverageGap? Gap,
    string? ChildVirtualPath,
    FormatProbe? ChildProbe,
    WorkerFailure? Failure);
