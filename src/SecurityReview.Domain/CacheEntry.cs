using SecurityReview.Domain.Scans;

namespace SecurityReview.Domain;

/// <summary>
/// An encrypted cache entry for a pipeline stage result. The cache key is
/// a lowercase hex-encoded SHA-256 fingerprint of all inputs that affect
/// the result. The encrypted payload is opaque to the domain layer.
/// </summary>
public sealed record CacheEntry(
    string CacheKey,
    string Stage,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset LastUsedAtUtc,
    ScanId? SourceScanId,
    byte[] EncryptedPayload)
{
    public static CacheEntry Create(
        string cacheKey,
        string stage,
        DateTimeOffset atUtc,
        ScanId? sourceScanId,
        byte[] encryptedPayload)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        ArgumentNullException.ThrowIfNull(encryptedPayload);
        if (encryptedPayload.Length == 0)
            throw new ArgumentException("Encrypted payload must not be empty.", nameof(encryptedPayload));

        return new CacheEntry(
            cacheKey,
            stage,
            atUtc,
            atUtc,
            sourceScanId,
            encryptedPayload);
    }
}
