using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

/// <summary>
/// Encrypted persistence for pipeline stage cache entries using the
/// <c>cache_entries</c> table. The encrypted payload is pre-encrypted by
/// the caller (CacheCoordinator); this repository handles only storage
/// and retrieval.
/// </summary>
public sealed class SqliteCacheRepository : ICacheRepository
{
    private readonly ISqliteConnectionFactory _factory;

    private const string Table = "cache_entries";
    private const int BatchSize = 500;

    public SqliteCacheRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task<CacheEntry?> GetByKeyAsync(string cacheKey,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT cache_key, stage, created_at_utc, last_used_at_utc,
                source_scan_id, encrypted_payload
            FROM cache_entries
            WHERE cache_key = @key;
            """;
        cmd.Parameters.AddWithValue("@key", cacheKey);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        return ReadCacheEntry(reader);
    }

    public async Task InsertOrReplaceAsync(CacheEntry entry,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT OR REPLACE INTO cache_entries
                (cache_key, stage, created_at_utc, last_used_at_utc,
                 source_scan_id, encrypted_payload)
            VALUES (@key, @stage, @created, @lastUsed, @sourceScanId, @payload);
            """;
        cmd.Parameters.AddWithValue("@key", entry.CacheKey);
        cmd.Parameters.AddWithValue("@stage", entry.Stage);
        cmd.Parameters.AddWithValue("@created", entry.CreatedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@lastUsed", entry.LastUsedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@sourceScanId",
            (object?)entry.SourceScanId?.Value.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@payload", (object)entry.EncryptedPayload);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateLastUsedAsync(string cacheKey, DateTimeOffset lastUsed,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            UPDATE cache_entries
            SET last_used_at_utc = @lastUsed
            WHERE cache_key = @key;
            """;
        cmd.Parameters.AddWithValue("@lastUsed", lastUsed.ToString("O"));
        cmd.Parameters.AddWithValue("@key", cacheKey);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteByKeyAsync(string cacheKey,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM cache_entries WHERE cache_key = @key;";
        cmd.Parameters.AddWithValue("@key", cacheKey);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteByScanIdAsync(ScanId scanId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM cache_entries WHERE source_scan_id = @scanId;";
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteByStageAsync(
        string stage,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        await using var connection = await _factory.OpenAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM cache_entries WHERE stage = @stage;";
        cmd.Parameters.AddWithValue("@stage", stage);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<long> GetTotalSizeBytesAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT COALESCE(SUM(LENGTH(encrypted_payload)), 0)
            FROM cache_entries;
            """;

        object? result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result is long l ? l : Convert.ToInt64(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    public async Task<IReadOnlyList<CacheEntry>> ListByStageOldestFirstAsync(
        string stage, int limit, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT cache_key, stage, created_at_utc, last_used_at_utc,
                source_scan_id, encrypted_payload
            FROM cache_entries
            WHERE stage = @stage
            ORDER BY last_used_at_utc ASC
            LIMIT @limit;
            """;
        cmd.Parameters.AddWithValue("@stage", stage);
        cmd.Parameters.AddWithValue("@limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var entries = new List<CacheEntry>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            entries.Add(ReadCacheEntry(reader));
        return entries;
    }

    public async Task DeleteBatchAsync(IReadOnlyList<string> cacheKeys,
        CancellationToken cancellationToken = default)
    {
        for (int offset = 0; offset < cacheKeys.Count; offset += BatchSize)
        {
            int batchCount = Math.Min(BatchSize, cacheKeys.Count - offset);
            await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var tx = connection.BeginTransaction();

            try
            {
                await using var cmd = connection.CreateCommand();
                cmd.CommandText = "DELETE FROM cache_entries WHERE cache_key = @key;";
                var param = cmd.Parameters.Add("@key", SqliteType.Text);

                for (int i = 0; i < batchCount; i++)
                {
                    param.Value = cacheKeys[offset + i];
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw;
            }
        }
    }

    private static CacheEntry ReadCacheEntry(SqliteDataReader reader)
    {
        var cacheKey = reader.GetString(0);
        var stage = reader.GetString(1);
        var createdAt = DateTimeOffset.Parse(reader.GetString(2),
            System.Globalization.CultureInfo.InvariantCulture);
        var lastUsed = DateTimeOffset.Parse(reader.GetString(3),
            System.Globalization.CultureInfo.InvariantCulture);
        ScanId? sourceScanId = reader.IsDBNull(4)
            ? null
            : new ScanId(Guid.Parse(reader.GetString(4)));

        byte[] payload = GetBlobBytes(reader, 5);

        return new CacheEntry(cacheKey, stage, createdAt, lastUsed, sourceScanId, payload);
    }

    private static byte[] GetBlobBytes(SqliteDataReader reader, int ordinal)
    {
        using var stream = reader.GetStream(ordinal);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }
}
