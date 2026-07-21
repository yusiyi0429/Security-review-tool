using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for scan runs.
/// </summary>
public interface IScanRepository
{
    Task InsertAsync(ScanRun scan, CancellationToken cancellationToken = default);
    Task<ScanRun?> GetByIdAsync(ScanId scanId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScanRun>> ListAsync(CancellationToken cancellationToken = default);
    Task<bool> TryTransitionAsync(ScanId scanId, ScanStatus expectedStatus, long expectedVersion,
        ScanStatus nextStatus, CancellationToken cancellationToken = default);
    Task UpdateAsync(ScanRun scan, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists scans whose status is among <paramref name="statuses"/>,
    /// ordered by <c>created_at_utc DESC</c>.
    /// </summary>
    Task<IReadOnlyList<ScanRun>> ListByStatusAsync(IReadOnlyList<ScanStatus> statuses,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the most recent prior scan for any of the supplied
    /// root paths (matched by stored rule-pack hash and LLM
    /// endpoint fingerprint), or <c>null</c> when none exists. Used
    /// by the rescan handler to anchor the diff against the previous
    /// scan of the same lineage.
    /// </summary>
    Task<ScanRun?> FindLatestPreviousAsync(
        string activeRulePackHash,
        string endpointFingerprint,
        CancellationToken cancellationToken = default);
}
