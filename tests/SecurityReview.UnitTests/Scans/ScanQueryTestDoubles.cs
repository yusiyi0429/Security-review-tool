using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

internal sealed class FakeScanRepository(ScanRun scan) : IScanRepository
{
    public Task InsertAsync(ScanRun value, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task<ScanRun?> GetByIdAsync(
        ScanId scanId,
        CancellationToken ct = default)
        => Task.FromResult<ScanRun?>(scan.ScanId == scanId ? scan : null);

    public Task<IReadOnlyList<ScanRun>> ListAsync(
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<ScanRun>>([scan]);

    public Task<bool> TryTransitionAsync(
        ScanId scanId,
        ScanStatus expectedStatus,
        long expectedVersion,
        ScanStatus nextStatus,
        CancellationToken ct = default)
        => Task.FromResult(false);

    public Task UpdateAsync(ScanRun value, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<ScanRun>> ListByStatusAsync(
        IReadOnlyList<ScanStatus> statuses,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<ScanRun>>(
            statuses.Contains(scan.Status) ? [scan] : []);

    public Task<ScanRun?> FindLatestPreviousAsync(
        string activeRulePackHash,
        string endpointFingerprint,
        CancellationToken ct = default)
        => Task.FromResult<ScanRun?>(scan);
}

internal sealed class FakeFindingRepository(
    ScanId scanId,
    IReadOnlyList<FindingGroup> groups) : IFindingRepository
{
    public Task InsertGroupAsync(
        ScanId id,
        FindingGroup group,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task InsertOccurrenceAsync(
        FileId fileId,
        FindingOccurrence occurrence,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task InsertOccurrenceBatchAsync(
        FileId fileId,
        IReadOnlyList<FindingOccurrence> occurrences,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task<FindingGroup?> GetGroupByIdAsync(
        FindingGroupId id,
        CancellationToken ct = default)
        => Task.FromResult(groups.FirstOrDefault(group => group.Id == id));

    public Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(
        ScanId id,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<FindingGroup>>(
            id == scanId ? groups : []);

    public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(
        FindingGroupId groupId,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<FindingOccurrence>>(
            groups.FirstOrDefault(group => group.Id == groupId)?.Occurrences
            ?? []);
}

internal sealed class FakeCoverageRepository : ICoverageRepository
{
    public Task InsertAsync(CoverageGap gap, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task InsertBatchAsync(
        IReadOnlyList<CoverageGap> gaps,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(
        ScanId scanId,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<CoverageGap>>([]);
}

internal sealed class FakeFileRepository(
    ScanId scanId,
    IReadOnlyList<FileRecord> files) : IFileRepository
{
    public Task InsertAsync(
        ScanId id,
        FileRecord file,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task InsertBatchAsync(
        ScanId id,
        IReadOnlyList<FileRecord> values,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task UpdateAsync(
        ScanId id,
        FileRecord file,
        CancellationToken ct = default)
        => Task.CompletedTask;

    public Task<FileRecord?> GetByIdAsync(
        FileId fileId,
        CancellationToken ct = default)
        => Task.FromResult(files.FirstOrDefault(file => file.FileId == fileId));

    public Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(
        ScanId id,
        CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<FileRecord>>(
            id == scanId ? files : []);

    public Task<int> CountByScanIdAsync(
        ScanId id,
        CancellationToken ct = default)
        => Task.FromResult(id == scanId ? files.Count : 0);
}

internal sealed class FakeReviewService : IReviewService
{
    public Task<ReviewDecision> RecordReviewAsync(
        RecordReviewCommand command,
        CancellationToken ct = default)
        => throw new NotSupportedException();

    public Task<ExceptionGrant> GrantExceptionAsync(
        GrantExceptionCommand command,
        CancellationToken ct = default)
        => throw new NotSupportedException();

    public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
        FindingOccurrenceId occurrenceId,
        string assetBindingHmac,
        string occurrenceBindingHmac,
        CancellationToken ct = default)
        => Task.FromResult(new EffectiveReviewResult(
            SecurityReview.Domain.Reviews.ReviewStatus.Pending,
            "pending",
            null));
}

/// <summary>
/// Reversible no-op "protector" for query-side tests: the payload is
/// just base64 of the plaintext so the snapshot codec round-trips.
/// </summary>
internal sealed class FakePayloadProtector : IPayloadProtector
{
    public EncryptedPayload Protect(
        string table, string recordId, string fieldName, byte[] plaintext) =>
        new(1, "test-key", "", Convert.ToBase64String(plaintext), "");

    public byte[] Unprotect(
        string table, string recordId, string fieldName, EncryptedPayload payload) =>
        Convert.FromBase64String(payload.CiphertextBase64);
}

internal sealed class FakeScanSnapshotRepository(
    ScanSnapshotRecord? record) : IScanSnapshotRepository
{
    public Task InsertAsync(
        ScanId scanId,
        ScanSnapshotRecord value,
        CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<ScanSnapshotRecord?> GetByScanIdAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default)
        => Task.FromResult(
            record is not null && record.ScanId == scanId ? record : null);

    public Task<string?> GetConfigHashAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default)
        => Task.FromResult(
            record is not null && record.ScanId == scanId ? record.ConfigHash : null);
}

/// <summary>
/// Builds minimal but hash-valid scan configuration snapshots for tests.
/// </summary>
internal static class ScanTestData
{
    public static ScanConfigurationSnapshot BuildSnapshot(params string[] rootPaths) =>
        new(
            RootPaths: rootPaths,
            Manifest: new ManifestSnapshot(
                Manifest: null,
                OriginalSha256: "manifest-hash",
                Valid: true,
                Errors: Array.Empty<ManifestValidationError>()),
            UiOverrideComponentIds: Array.Empty<string>(),
            ExclusionPatterns: Array.Empty<string>(),
            ActiveRulePackHash: "rule-pack-hash",
            PolicySha256: "policy-sha",
            LlmEndpointFingerprint: "endpoint-fp",
            LlmModelFingerprint: "model-fp",
            ClientVersion: "client-v1",
            ParserAdapterVersion: "parser-v1",
            DetectorAdapterVersion: "detector-v1",
            PromptVersion: "prompt-v1",
            Sandbox: new SandboxSelfTestResult(
                true, "ok", "worker-sha", "os-build", "profile-sid",
                DateTimeOffset.UnixEpoch),
            EffectiveDetectorVersions: ["detector-v1"],
            CapturedAtUtc: DateTimeOffset.UnixEpoch);

    public static ScanSnapshotRecord BuildRecord(
        ScanId scanId,
        IPayloadProtector protector,
        params string[] rootPaths)
    {
        ScanConfigurationSnapshot snapshot = BuildSnapshot(rootPaths);
        var codec = new ScanConfigurationSnapshotCodec(protector);
        return new ScanSnapshotRecord(
            scanId,
            snapshot.CapturedAtUtc,
            snapshot.ComputeHash(),
            snapshot.ActiveRulePackHash,
            snapshot.PolicySha256,
            snapshot.LlmEndpointFingerprint,
            snapshot.LlmModelFingerprint,
            snapshot.ClientVersion,
            snapshot.ParserAdapterVersion,
            snapshot.DetectorAdapterVersion,
            snapshot.PromptVersion,
            snapshot.Sandbox.WorkerSha256,
            codec.Protect(scanId, snapshot));
    }
}
