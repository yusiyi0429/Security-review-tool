using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for stage-level cache entries supporting
/// parse, detect, and semantic review reuse decisions.
/// </summary>
public interface ICacheRepository
{
    /// <summary>
    /// Retrieves a cache entry by its hex-encoded cache key, or null
    /// when no entry exists.
    /// </summary>
    Task<CacheEntry?> GetByKeyAsync(string cacheKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Inserts a new cache entry or replaces an existing entry with the
    /// same key. The caller must encrypt the payload before storage.
    /// </summary>
    Task InsertOrReplaceAsync(CacheEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the last-used timestamp of an existing cache entry.
    /// </summary>
    Task UpdateLastUsedAsync(string cacheKey, DateTimeOffset lastUsed,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a cache entry by key. Safe to call when the key does not exist.
    /// </summary>
    Task DeleteByKeyAsync(string cacheKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes all cache entries associated with a scan.
    /// </summary>
    Task DeleteByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default);

    Task DeleteByStageAsync(string stage, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the total size (bytes) of all cached encrypted payloads.
    /// </summary>
    Task<long> GetTotalSizeBytesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns cache entries for a given stage, ordered by last-used
    /// ascending (oldest first), up to the specified limit.
    /// </summary>
    Task<IReadOnlyList<CacheEntry>> ListByStageOldestFirstAsync(string stage, int limit,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes the specified cache entries in a single transaction.
    /// </summary>
    Task DeleteBatchAsync(IReadOnlyList<string> cacheKeys, CancellationToken cancellationToken = default);
}
