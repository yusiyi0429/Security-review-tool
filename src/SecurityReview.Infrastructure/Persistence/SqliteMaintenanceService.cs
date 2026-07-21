using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Database maintenance operations: scan cascade deletion, cache
/// cleanup, WAL checkpoint, and conditional VACUUM.
/// </summary>
public sealed class SqliteMaintenanceService : IDatabaseMaintenanceService
{
    private readonly ISqliteConnectionFactory _factory;
    private const int BatchSize = 100;

    // FK cascade deletion order — must execute in this order to satisfy FK constraints.
    private static readonly string[] CascadeDeleteTables =
    [
        "review_decisions",    // FKs: scan_id, group_id, occurrence_id
        "finding_occurrences", // FKs: group_id, file_id
        "finding_groups",      // FK: scan_id
        "coverage_gaps",       // FKs: scan_id, file_id
        "llm_reviews",         // FK: scan_id
        "diagnostic_events",   // FK: scan_id
        "file_records",        // FK: scan_id
        "assets",              // FK: scan_id
    ];

    public SqliteMaintenanceService(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    /// <inheritdoc />
    public async Task<int> DeleteExpiredScansAsync(
        IReadOnlyList<ScanId> scanIds, CancellationToken cancellationToken = default)
    {
        if (scanIds.Count == 0)
            return 0;

        int deleted = 0;

        for (int offset = 0; offset < scanIds.Count; offset += BatchSize)
        {
            int batchCount = Math.Min(BatchSize, scanIds.Count - offset);
            var batch = new List<ScanId>(batchCount);
            for (int i = 0; i < batchCount; i++)
                batch.Add(scanIds[offset + i]);

            deleted += await DeleteBatchAsync(batch, cancellationToken).ConfigureAwait(false);
        }

        return deleted;
    }

    private async Task<int> DeleteBatchAsync(
        IReadOnlyList<ScanId> scanIds, CancellationToken cancellationToken)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = connection.BeginTransaction();

        try
        {
            int deleted = await DeleteScanCascadeAsync(connection, scanIds, cancellationToken)
                .ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            return deleted;
        }
        catch
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<int> DeleteScanCascadeAsync(
        SqliteConnection connection,
        IReadOnlyList<ScanId> scanIds,
        CancellationToken cancellationToken)
    {
        var idStrings = scanIds.Select(s => s.Value.ToString()).ToList();

        // Delete from child tables first.
        foreach (var table in CascadeDeleteTables)
        {
            await DeleteByScanIdsAsync(connection, table, "scan_id", idStrings, cancellationToken)
                .ConfigureAwait(false);
        }

        // Delete the scan_runs themselves.
        await using var cmd = connection.CreateCommand();
        var placeholders = BuildParameterList(cmd, "@sid", idStrings);
        cmd.CommandText = $"DELETE FROM scan_runs WHERE scan_id IN ({placeholders});";
        int rows = await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return rows;
    }

    private static async Task DeleteByScanIdsAsync(
        SqliteConnection connection,
        string table,
        string column,
        List<string> idStrings,
        CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();
        var placeholders = BuildParameterList(cmd, "@sid", idStrings);
        cmd.CommandText = $"DELETE FROM {table} WHERE {column} IN ({placeholders});";
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<int> DeleteUnreferencedCacheAsync(
        DateTimeOffset? lastUsedThreshold, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = connection.BeginTransaction();

        try
        {
            int total = 0;
            await using var cmd = connection.CreateCommand();

            // Delete cache entries whose source_scan_id references a deleted scan.
            cmd.CommandText = """
                DELETE FROM cache_entries
                WHERE source_scan_id IS NOT NULL
                  AND source_scan_id NOT IN (SELECT scan_id FROM scan_runs);
                """;
            total += await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            // Delete cache entries older than the last-used threshold.
            if (lastUsedThreshold.HasValue)
            {
                cmd.CommandText = """
                    DELETE FROM cache_entries
                    WHERE last_used_at_utc < @threshold;
                    """;
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("@threshold", lastUsedThreshold.Value.ToString("O"));
                total += await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            return total;
        }
        catch
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task CheckpointWalAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<VacuumResult> TryVacuumAsync(
        bool hasActiveScan, CancellationToken cancellationToken = default)
    {
        if (hasActiveScan)
            return VacuumResult.NotEligible("An active scan or export is in progress.");

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);

        // Check free-page ratio.
        var freeRatio = await GetFreePageRatioAsync(connection, cancellationToken).ConfigureAwait(false);
        if (freeRatio < 0.25)
            return VacuumResult.NotEligible(
                $"Free-page ratio ({freeRatio:P1}) is below the 25 % threshold.");

        // Check disk space: need at least the DB size of free space for a copy.
        var dbPath = connection.DataSource;
        if (!HasEnoughDiskSpace(dbPath))
            return VacuumResult.NotEligible("Insufficient disk space for VACUUM copy.");

        // Run VACUUM.
        try
        {
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = "VACUUM;";
            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return VacuumResult.AppliedSuccessfully();
        }
        catch (Exception ex)
        {
            // VACUUM failure is diagnostic — the database is still usable.
            return VacuumResult.NotApplied($"VACUUM failed: {ex.Message}");
        }
    }

    private static async Task<double> GetFreePageRatioAsync(
        SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA freelist_count;";
        var freePagesObj = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        long freePages = freePagesObj is long fp ? fp : 0;

        cmd.CommandText = "PRAGMA page_count;";
        var totalPagesObj = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        long totalPages = totalPagesObj is long tp ? tp : 1;

        return totalPages > 0 ? (double)freePages / totalPages : 0;
    }

    private static bool HasEnoughDiskSpace(string dbPath)
    {
        try
        {
            var dbFile = new FileInfo(dbPath);
            if (!dbFile.Exists)
                return true;

            var root = Path.GetPathRoot(dbPath);
            if (root is null)
                return false;

            var drive = new DriveInfo(root);
            return drive.AvailableFreeSpace >= dbFile.Length;
        }
        catch
        {
            // If we can't determine disk space, err on the side of safety.
            return false;
        }
    }

    private static string BuildParameterList(
        SqliteCommand cmd, string prefix, List<string> values)
    {
        var names = new List<string>(values.Count);
        for (int i = 0; i < values.Count; i++)
        {
            var name = $"{prefix}{i}";
            names.Add(name);
            cmd.Parameters.AddWithValue(name, values[i]);
        }
        return string.Join(", ", names);
    }
}
