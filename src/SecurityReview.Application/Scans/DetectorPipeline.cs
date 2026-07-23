using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Default <see cref="IDetectionPipeline"/>. Fans out one chunk to every
/// registered <see cref="IDetector"/> and concatenates their output.
/// Each candidate retains its originating detector id; the candidate
/// merger later collapses duplicates by value fingerprint.
/// </summary>
public sealed class DetectorPipeline : IDetectionPipeline
{
    private readonly IReadOnlyList<IDetector> _detectors;

    public DetectorPipeline(IReadOnlyList<IDetector> detectors)
    {
        _detectors = detectors ?? throw new ArgumentNullException(nameof(detectors));
    }

    public async IAsyncEnumerable<DetectionCandidate> DetectAsync(
        ScanId scanId,
        JobId jobId,
        FileId fileId,
        string fileSha256,
        string virtualPath,
        string rulePackHash,
        IReadOnlyList<AssetTypeId> assetTypes,
        ContentChunk chunk,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        _ = rulePackHash;
        _ = assetTypes;

        var context = new DetectionContext(scanId, jobId, fileId, fileSha256, virtualPath, chunk);

        foreach (IDetector detector in _detectors)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                yield break;
            }

            await foreach (DetectionCandidate candidate in detector
                .DetectAsync(context, cancellationToken)
                .ConfigureAwait(false))
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    yield break;
                }

                yield return candidate;
            }
        }
    }
}
