using SecurityReview.Domain;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Contract for database-level maintenance operations: scan cascade
/// deletion, cache cleanup, WAL checkpoint, and VACUUM.
/// </summary>
public interface IDatabaseMaintenanceService
{
    /// <summary>
    /// Deletes a batch of expired scans and all dependent rows
    /// transactionally. Returns the count of scans actually deleted.
    /// </summary>
    Task<int> DeleteExpiredScansAsync(IReadOnlyList<ScanId> scanIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes cache entries whose <c>last_used_at_utc</c> is before
    /// the given threshold, or whose <c>source_scan_id</c> no longer
    /// references an existing scan. Returns the count of rows deleted.
    /// </summary>
    Task<int> DeleteUnreferencedCacheAsync(DateTimeOffset? lastUsedThreshold, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checkpoints the WAL to flush committed pages to the main
    /// database file.
    /// </summary>
    Task CheckpointWalAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs VACUUM when conditions are met: no active scan, free-page
    /// ratio ≥ 25 %, and enough disk space for a copy. Returns a
    /// diagnostic result.
    /// </summary>
    Task<VacuumResult> TryVacuumAsync(bool hasActiveScan, CancellationToken cancellationToken = default);
}

/// <summary>
/// Outcome of a VACUUM attempt.
/// </summary>
public sealed record VacuumResult(
    bool Applied,
    bool Eligible,
    string Diagnostic)
{
    public static VacuumResult AppliedSuccessfully() => new(true, true, "VACUUM completed successfully.");
    public static VacuumResult NotEligible(string reason) => new(false, false, reason);
    public static VacuumResult NotApplied(string reason) => new(false, true, reason);
}
