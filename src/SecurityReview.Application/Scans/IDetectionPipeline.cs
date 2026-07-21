using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Contract that wires parser chunks through the detection pipeline
/// and persists the resulting <see cref="DetectionCandidate"/> rows.
/// The default implementation is provided by P2 (real detectors);
/// P5-T4 ships an in-process shim that the orchestrator uses when no
/// real detector is registered.
///
/// Returned <see cref="DetectionResult"/> records are appended-only;
/// the orchestrator never re-emits a candidate that has already been
/// persisted for the current scan.
/// </summary>
public interface IDetectionPipeline
{
    /// <summary>
    /// Runs detection on <paramref name="chunk"/> and returns every
    /// candidate the detectors produced. The caller persists each
    /// candidate through <see cref="IFindingRepository"/> before
    /// returning to the pipeline.
    /// </summary>
    IAsyncEnumerable<DetectionCandidate> DetectAsync(
        ScanId scanId,
        JobId jobId,
        FileId fileId,
        string fileSha256,
        string virtualPath,
        ContentChunk chunk,
        CancellationToken cancellationToken);
}

/// <summary>
/// Stateless helper that yields a single <see cref="DetectionCandidate"/>
/// for one chunk. Implementations decide which chunk fields to inspect
/// (rule patterns, regex, entropy, ...) and produce zero, one, or many
/// candidates. The base contract is intentionally tiny so test doubles
/// can stand in for the production detectors.
/// </summary>
public interface IDetector
{
    string DetectorId { get; }

    IAsyncEnumerable<DetectionCandidate> DetectAsync(
        DetectionContext context,
        CancellationToken cancellationToken);
}

/// <summary>
/// Per-chunk detector input. Carries the file identity, the chunk
/// content, and the locator for any candidate the detector chooses to
/// emit.
/// </summary>
public sealed record DetectionContext(
    ScanId ScanId,
    JobId JobId,
    FileId FileId,
    string FileSha256,
    string VirtualPath,
    ContentChunk Chunk);
