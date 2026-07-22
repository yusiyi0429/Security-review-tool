using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Drives one scan from preflight through coverage reconciliation and
/// final <see cref="ScanStatus"/> reporting. The orchestrator owns the
/// state machine transitions Draft → Preflight → Running →
/// Completed/Partial/Failed/Cancelled.
///
/// The implementation:
///   1. Re-hashes every file and applies one mutation retry.
///   2. For each parsed chunk, runs detectors and encrypts/persists
///      every candidate immediately.
///   3. Enqueues only candidates flagged
///      <see cref="DetectionCandidate.RequiresSemanticReview"/> and
///      awaits the queue drain (unless cancelled).
///   4. Records <c>LlmUnresolved</c> gaps for unresolved candidates.
///   5. Produces a final reconciliation and diff (with the previous
///      scan in the same lineage when one exists).
/// </summary>
public interface IScanOrchestrator
{
    /// <summary>
    /// Executes the scan identified by <paramref name="scanId"/> using
    /// the immutable <paramref name="snapshot"/>. Yields progress
    /// updates and returns when the scan reaches a terminal state.
    /// </summary>
    IAsyncEnumerable<ScanProgress> RunAsync(
        ScanId scanId,
        ScanConfigurationSnapshot snapshot,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the last terminal <see cref="ScanStatus"/> observed by
    /// the orchestrator for <paramref name="scanId"/>. The orchestrator
    /// records the outcome after the progress stream completes.
    /// </summary>
    Task<ScanOutcome?> GetOutcomeAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Final outcome of one scan. The orchestrator records it after the
/// last progress event is delivered; the read path uses it for the
/// <see cref="ScanQueryService"/> projections.
/// </summary>
public sealed record ScanOutcome(
    ScanId ScanId,
    ScanStatus FinalStatus,
    int FindingCount,
    int UnresolvedSemanticCount,
    int GapCount,
    DateTimeOffset CompletedAtUtc);
