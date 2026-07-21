using SecurityReview.Domain;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Stores the immutable preflight <see cref="Scans.ScanConfigurationSnapshot"/>
/// for every scan run. The snapshot's hash is the auditable reference; the
/// row is created at <c>CreateScanHandler</c> time and never mutated — any
/// post-Start UI edit only affects a future scan.
/// </summary>
public interface IScanSnapshotRepository
{
    /// <summary>
    /// Inserts the snapshot for a freshly created scan. Throws when the
    /// scan already has a snapshot.
    /// </summary>
    Task InsertAsync(ScanId scanId, ScanSnapshotRecord record, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the stored snapshot for a scan, or <c>null</c> when none
    /// has been persisted yet.
    /// </summary>
    Task<ScanSnapshotRecord?> GetByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the SHA-256 hash recorded for the snapshot — a fast
    /// path for callers that only need the hash, not the full record.
    /// </summary>
    Task<string?> GetConfigHashAsync(ScanId scanId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Lookup helpers on <see cref="IScanSnapshotRepository"/>. Kept as an
/// extension surface so production code uses the async API and tests
/// can synchronously read the cached record.
/// </summary>
public static class ScanSnapshotRepositoryExtensions
{
    /// <summary>
    /// Synchronous read of the stored snapshot, intended for callers
    /// that have just inserted the row and want to assert against its
    /// contents without a follow-up round-trip.
    /// </summary>
    public static ScanSnapshotRecord? Get(this IScanSnapshotRepository repository, ScanId scanId)
    {
        ArgumentNullException.ThrowIfNull(repository);
        return repository.GetByScanIdAsync(scanId, CancellationToken.None)
            .GetAwaiter().GetResult();
    }
}

/// <summary>
/// Plain-column projection of a stored snapshot. Encrypted fields are
/// returned as raw bytes; callers decrypt through <see cref="IPayloadProtector"/>.
/// </summary>
public sealed record ScanSnapshotRecord(
    ScanId ScanId,
    DateTimeOffset CapturedAtUtc,
    string ConfigHash,
    string ActiveRulePackHash,
    string PolicySha256,
    string LlmEndpointFingerprint,
    string LlmModelFingerprint,
    string ClientVersion,
    string ParserAdapterVersion,
    string DetectorAdapterVersion,
    string PromptVersion,
    string SandboxWorkerSha256,
    byte[] EncryptedPayload);
