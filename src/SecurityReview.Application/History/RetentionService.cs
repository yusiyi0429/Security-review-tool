using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;

namespace SecurityReview.Application.History;

/// <summary>
/// Orchestrates retention cleanup by evaluating which scans are expired
/// and delegating cascade deletion to the database maintenance service.
/// </summary>
public sealed class RetentionService
{
    private readonly IScanRepository _scanRepository;
    private readonly IDatabaseMaintenanceService _maintenanceService;

    public RetentionService(IScanRepository scanRepository, IDatabaseMaintenanceService maintenanceService)
    {
        _scanRepository = scanRepository;
        _maintenanceService = maintenanceService;
    }

    /// <summary>
    /// Evaluates all scans against <paramref name="period"/> and deletes
    /// expired ones. Returns a report with the counts of deleted and
    /// preserved scans. Cache entries referencing deleted scans are also
    /// cleaned up. A WAL checkpoint is performed at the end.
    /// </summary>
    public async Task<RetentionResult> PurgeExpiredAsync(
        RetentionPeriod period, CancellationToken cancellationToken = default)
    {
        if (period == RetentionPeriod.Permanent)
            return new RetentionResult(CanDelete: false, Deleted: 0, Preserved: 0);

        var allScans = await _scanRepository.ListAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;

        var expired = new List<ScanId>();
        var preserved = new List<ScanId>();

        foreach (var scan in allScans)
        {
            if (RetentionPolicy.IsExpired(scan, period, now))
                expired.Add(scan.ScanId);
            else
                preserved.Add(scan.ScanId);
        }

        if (expired.Count == 0)
            return new RetentionResult(CanDelete: true, Deleted: 0, Preserved: preserved.Count);

        int deleted = await _maintenanceService.DeleteExpiredScansAsync(expired, cancellationToken)
            .ConfigureAwait(false);

        // Clean up cache entries that reference now-deleted scans, and
        // also evict cache older than the same retention threshold.
        var cacheThreshold = RetentionPolicy.ExpiryThreshold(period, now);
        if (cacheThreshold != DateTimeOffset.MinValue)
        {
            await _maintenanceService.DeleteUnreferencedCacheAsync(cacheThreshold, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            await _maintenanceService.DeleteUnreferencedCacheAsync(null, cancellationToken)
                .ConfigureAwait(false);
        }

        await _maintenanceService.CheckpointWalAsync(cancellationToken).ConfigureAwait(false);

        return new RetentionResult(CanDelete: true, Deleted: deleted, Preserved: preserved.Count);
    }

    /// <summary>
    /// Evaluates which scan IDs would be deleted under the given period
    /// without actually performing deletion. Used for dry-run/preview.
    /// </summary>
    public async Task<IReadOnlyList<ScanId>> PreviewExpiredAsync(
        RetentionPeriod period, CancellationToken cancellationToken = default)
    {
        if (period == RetentionPeriod.Permanent)
            return Array.Empty<ScanId>();

        var allScans = await _scanRepository.ListAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;

        return allScans
            .Where(s => RetentionPolicy.IsExpired(s, period, now))
            .Select(s => s.ScanId)
            .ToList();
    }

    public async Task<bool> DeleteScanAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default)
    {
        int deleted = await _maintenanceService
            .DeleteExpiredScansAsync([scanId], cancellationToken)
            .ConfigureAwait(false);
        if (deleted == 0)
            return false;

        await _maintenanceService
            .DeleteUnreferencedCacheAsync(null, cancellationToken)
            .ConfigureAwait(false);
        await _maintenanceService
            .CheckpointWalAsync(cancellationToken)
            .ConfigureAwait(false);
        return true;
    }
}

/// <summary>
/// Result of a retention purge operation.
/// </summary>
/// <param name="CanDelete"><c>false</c> when the period is Permanent.</param>
/// <param name="Deleted">Number of scans cascade-deleted.</param>
/// <param name="Preserved">Number of scans kept in the database.</param>
public sealed record RetentionResult(bool CanDelete, int Deleted, int Preserved);
