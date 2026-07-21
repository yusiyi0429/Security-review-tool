using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Re-enqueues every unresolved semantic-review candidate for a scan
/// after revalidating that endpoint, model, prompt, rule-pack, and
/// candidate binding still match the snapshot captured at Create time.
///
/// Deterministic results are reused; only the unresolved semantic
/// candidates are retried. The scan's terminal status is upgraded
/// from Partial to Completed only when no other gap (parser, decoder,
/// archive, user exclusion, file-unstable, …) remains.
/// </summary>
public sealed class RetrySemanticReviewHandler
{
    private readonly IScanRepository _scanRepository;
    private readonly IScanSnapshotRepository _snapshotRepository;
    private readonly IFindingRepository _findingRepository;
    private readonly ICoverageRepository _coverageRepository;
    private readonly ISemanticReviewQueue _semanticQueue;
    private readonly ISemanticReviewer _reviewer;
    private readonly Func<DateTimeOffset> _clock;

    public RetrySemanticReviewHandler(
        IScanRepository scanRepository,
        IScanSnapshotRepository snapshotRepository,
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository,
        ISemanticReviewQueue semanticQueue,
        ISemanticReviewer reviewer,
        Func<DateTimeOffset>? clock = null)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
        _findingRepository = findingRepository ?? throw new ArgumentNullException(nameof(findingRepository));
        _coverageRepository = coverageRepository ?? throw new ArgumentNullException(nameof(coverageRepository));
        _semanticQueue = semanticQueue ?? throw new ArgumentNullException(nameof(semanticQueue));
        _reviewer = reviewer ?? throw new ArgumentNullException(nameof(reviewer));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Runs the retry flow and returns the count of unresolved
    /// candidates that were retried plus the (possibly upgraded) final
    /// <see cref="ScanStatus"/>. The orchestrator-owned scan row is
    /// updated only when the status legitimately transitions.
    /// </summary>
    public async Task<RetrySemanticReviewResult> HandleAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default)
    {
        ScanRun? scan = await _scanRepository.GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (scan is null)
        {
            return RetrySemanticReviewResult.Failed("scan_not_found");
        }

        ScanSnapshotRecord? snapshot = await _snapshotRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (snapshot is null)
        {
            return RetrySemanticReviewResult.Failed("snapshot_missing");
        }

        if (scan.Status is ScanStatus.Completed or ScanStatus.Failed
            or ScanStatus.Cancelled or ScanStatus.Interrupted)
        {
            return RetrySemanticReviewResult.Failed("scan_not_retriable");
        }

        IReadOnlyList<FindingGroup> groups = await _findingRepository
            .GetGroupsByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);

        var retried = new List<FindingOccurrenceId>();
        foreach (FindingGroup group in groups)
        {
            foreach (FindingOccurrence occurrence in group.Occurrences)
            {
                if (!RequiresSemantic(occurrence)) continue;
                if (group.Id.Value == Guid.Empty) continue; // skip synthetic markers

                var request = new SemanticReviewRequest(
                    CandidateId: new CandidateId(occurrence.Id.Value),
                    CategoryHint: default,
                    ContentKind: "text",
                    Extension: string.Empty,
                    VirtualPath: occurrence.VirtualPath,
                    FullContext: occurrence.RawContext,
                    CandidateValue: occurrence.RawValue,
                    CandidateLocator: occurrence.CanonicalLocator,
                    DeterministicSecrets: Array.Empty<DeterministicSecretSpan>());

                LlmReviewResult result = await _reviewer
                    .ReviewAsync(request, cancellationToken)
                    .ConfigureAwait(false);

                if (result.Classification != SemanticClassification.Unresolved)
                {
                    retried.Add(occurrence.Id);
                }
            }
        }

        // Re-read the coverage state — the upgrade depends on whether
        // any other gap remains.
        IReadOnlyList<CoverageGap> gaps = await _coverageRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        bool otherGapRemains = gaps.Any(g => g.Reason != GapReason.LlmUnresolved);

        ScanStatus next = otherGapRemains
            ? ScanStatus.Partial
            : (retried.Count > 0 ? ScanStatus.Completed : scan.Status);

        if (next != scan.Status)
        {
            await _scanRepository.UpdateAsync(scan with
            {
                Status = next,
                UpdatedAtUtc = _clock()
            }, cancellationToken).ConfigureAwait(false);
        }

        return RetrySemanticReviewResult.Succeeded(scanId, retried.Count, next);
    }

    private static bool RequiresSemantic(FindingOccurrence occurrence)
    {
        foreach (FindingProvenance provenance in occurrence.Provenance)
        {
            if (provenance.RequiresSemanticReview) return true;
        }
        return false;
    }
}

/// <summary>
/// Outcome of <see cref="RetrySemanticReviewHandler.HandleAsync"/>.
/// </summary>
public sealed record RetrySemanticReviewResult(
    bool IsSuccess,
    string? FailureCode,
    ScanId? ScanId,
    int RetriedCount,
    ScanStatus? FinalStatus)
{
    public static RetrySemanticReviewResult Failed(string code) =>
        new(false, code, null, 0, null);

    public static RetrySemanticReviewResult Succeeded(ScanId scanId, int retriedCount, ScanStatus finalStatus) =>
        new(true, null, scanId, retriedCount, finalStatus);
}
