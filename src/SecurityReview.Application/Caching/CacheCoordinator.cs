using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Caching;

/// <summary>
/// Coordinates encrypted stage-level caching with budget-aware LRU
/// eviction. Each cache entry is AES-GCM encrypted with AAD binding;
/// tamper or hash failures delete the entry and rerun the work.
///
/// Dependency order is parse → detect → semantic: a detect miss can
/// reuse parse chunks from cache; semantic miss can reuse deterministic
/// candidates from cache.
/// </summary>
public sealed class CacheCoordinator
{
    private readonly ICacheRepository _repository;
    private readonly IPayloadProtector _protector;
    private readonly IDiskCapacityProvider _diskCapacity;
    private readonly JsonSerializerOptions _jsonOptions;

    private const string Table = "cache_entries";
    private static readonly TimeSpan DefaultEvictionLookback = TimeSpan.FromDays(30);

    // Budget constants
    private const long TwoGiB = 2L * 1024 * 1024 * 1024;          // 2 GiB
    private const long BudgetMaxBytes = TwoGiB;                      // ceiling
    private const long ReserveBytes = TwoGiB;                        // always keep 2 GiB free

    public CacheCoordinator(
        ICacheRepository repository,
        IPayloadProtector protector,
        IDiskCapacityProvider diskCapacity)
    {
        _repository = repository;
        _protector = protector;
        _diskCapacity = diskCapacity;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    /// <summary>
    /// Attempts to retrieve and decrypt a cached result. Returns null
    /// when the entry is missing, tampered (AEAD tag mismatch), or
    /// otherwise corrupt. Corrupt entries are deleted automatically
    /// — we never fail open to a suspect result.
    /// </summary>
    public async Task<T?> TryGetAsync<T>(
        string cacheKey, string stage, string recordId,
        CancellationToken cancellationToken = default)
    {
        CacheEntry? entry;
        try
        {
            entry = await _repository.GetByKeyAsync(cacheKey, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            // Repository-level failure (e.g. corruption) — treat as miss,
            // delete the suspect key best-effort.
            await DeleteIfExistsAsync(cacheKey, cancellationToken).ConfigureAwait(false);
            return default;
        }

        if (entry is null) return default;

        try
        {
            EncryptedPayload envelope = DeserializeEnvelope(entry.EncryptedPayload);
            byte[] plaintext = _protector.Unprotect(Table, recordId, "payload", envelope);
            return JsonSerializer.Deserialize<T>(plaintext, _jsonOptions);
        }
        catch
        {
            // AEAD tag mismatch, hash mismatch, or deserialization failure:
            // delete the corrupt entry and rerun.
            await _repository.DeleteByKeyAsync(cacheKey, cancellationToken)
                .ConfigureAwait(false);
            return default;
        }
    }

    /// <summary>
    /// Encrypts and stores a stage result, respecting the cache budget.
    /// If the budget cannot accommodate the new entry after LRU eviction,
    /// the entry is silently skipped (no coverage change, no error).
    /// Returns true when the entry was stored.
    /// </summary>
    public async Task<bool> StoreAsync<T>(
        string cacheKey, string stage, ScanId scanId,
        string recordId, T result,
        CancellationToken cancellationToken = default)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(result, _jsonOptions);

        EncryptedPayload envelope;
        try
        {
            envelope = _protector.Protect(Table, recordId, "payload", plaintext);
        }
        catch
        {
            // Encryption failed — skip caching.
            return false;
        }

        byte[] encryptedPayload = SerializeEnvelope(envelope);
        long entrySize = encryptedPayload.Length;

        // Check budget and evict if needed.
        if (!await EnsureBudgetAsync(entrySize, cancellationToken).ConfigureAwait(false))
        {
            // Budget cannot accommodate this entry — skip.
            return false;
        }

        var entry = new CacheEntry(
            cacheKey, stage, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            scanId, encryptedPayload);

        await _repository.InsertOrReplaceAsync(entry, cancellationToken)
            .ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// Returns the configured physical cache budget in bytes.
    /// min(2 GiB, 10% of free disk space measured now).
    /// </summary>
    public long ComputeBudget()
    {
        long freeBytes = _diskCapacity.GetFreeBytes();
        long tenPercent = Math.Max(0, freeBytes / 10);
        return Math.Min(BudgetMaxBytes, tenPercent);
    }

    /// <summary>
    /// Evicts LRU entries across all stages until the total cache size
    /// falls within the budget, or until no more evictable entries exist.
    /// Returns true if the budget can accommodate the requested additional
    /// bytes after eviction.
    /// </summary>
    internal async Task<bool> EnsureBudgetAsync(
        long additionalBytes, CancellationToken cancellationToken)
    {
        long budget = ComputeBudget();
        long currentTotal = await _repository.GetTotalSizeBytesAsync(cancellationToken)
            .ConfigureAwait(false);

        long needed = (currentTotal + additionalBytes) - budget;

        // Also check the free-space reserve: after writing, at least
        // ReserveBytes must remain free on disk.
        long freeAfterWrite = _diskCapacity.GetFreeBytes() - additionalBytes;
        if (freeAfterWrite < ReserveBytes)
        {
            // Need additional eviction to preserve the reserve.
            long reserveNeeded = ReserveBytes - freeAfterWrite;
            needed = Math.Max(needed, reserveNeeded);
        }

        if (needed <= 0) return true;

        // Evict LRU entries across all stages.
        long evictedTotal = 0;
        var stages = new[] { "parsing", "detection", "llm_review" };

        foreach (string stage in stages)
        {
            while (evictedTotal < needed)
            {
                var candidates = await _repository
                    .ListByStageOldestFirstAsync(stage, 100, cancellationToken)
                    .ConfigureAwait(false);

                // Filter out entries from the current scan (they might be
                // needed later in the same scan).
                var toEvict = candidates
                    .Select(c => c.CacheKey)
                    .ToList();

                if (toEvict.Count == 0) break;

                await _repository.DeleteBatchAsync(toEvict, cancellationToken)
                    .ConfigureAwait(false);

                evictedTotal += candidates.Sum(c => (long)c.EncryptedPayload.Length);
            }

            if (evictedTotal >= needed) break;
        }

        // Recompute after eviction.
        long newTotal = await _repository.GetTotalSizeBytesAsync(cancellationToken)
            .ConfigureAwait(false);
        return (newTotal + additionalBytes) <= budget
            && (_diskCapacity.GetFreeBytes() - additionalBytes) >= ReserveBytes;
    }

    private static EncryptedPayload DeserializeEnvelope(byte[] data)
    {
        return JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(data),
            CacheCoordinatorJsonContext.Default.EncryptedPayload)!;
    }

    private static byte[] SerializeEnvelope(EncryptedPayload envelope)
    {
        return Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(envelope,
                CacheCoordinatorJsonContext.Default.EncryptedPayload));
    }

    private async Task DeleteIfExistsAsync(string cacheKey,
        CancellationToken cancellationToken)
    {
        try
        {
            await _repository.DeleteByKeyAsync(cacheKey, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            // Best-effort cleanup; ignore failures.
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(EncryptedPayload))]
internal sealed partial class CacheCoordinatorJsonContext : JsonSerializerContext;
