using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class OccurrenceFileLocationTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public OccurrenceFileLocationTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-fileloc-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        _hkdf = new HkdfSha256(masterKey);
        _protector = new AesGcmPayloadProtector(
            _hkdf.DeriveEncryptionKey(), "test-key");
        _fingerprint = new PersistentValueFingerprintService(
            _hkdf.DeriveFingerprintKey());

        using var init = new SqliteConnection(
            $"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        new Migration001Initial()
            .ApplyAsync(init, "test-integration", CancellationToken.None)
            .GetAwaiter().GetResult();
        new Migration003ScanSnapshots()
            .ApplyAsync(init, "test-integration", CancellationToken.None)
            .GetAwaiter().GetResult();
        init.Close();
    }

    [Fact]
    public async Task Resolves_absolute_path_for_second_root_and_nested_entry()
    {
        // Arrange: two real roots; the hit file exists under root B.
        string rootA = Path.Combine(_tempDir, "rootA");
        string rootB = Path.Combine(_tempDir, "rootB");
        Directory.CreateDirectory(rootA);
        Directory.CreateDirectory(Path.Combine(rootB, "conf"));
        string realFile = Path.Combine(rootB, "conf", "app.json");
        await File.WriteAllTextAsync(realFile, "{}");
        string fileHash = new string('a', 64);

        var scans = new SqliteScanRepository(_factory, _protector);
        var files = new SqliteFileRepository(_factory, _protector, _fingerprint);
        var findings = new SqliteFindingRepository(_factory, _protector, _fingerprint);
        var coverage = new SqliteCoverageRepository(_factory, _protector);
        var snapshots = new SqliteScanSnapshotRepository(_factory);

        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Completed, now, now,
            "rule-fp", "client-v1", "pipeline-hash",
            PlannedCount: 1, Version: 1);
        await scans.InsertAsync(scan);

        var codec = new ScanConfigurationSnapshotCodec(_protector);
        ScanConfigurationSnapshot snapshot = ScanSnapshotBuilder.Build(
            rootA, rootB);
        var record = new ScanSnapshotRecord(
            scan.ScanId,
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
            codec.Protect(scan.ScanId, snapshot));
        await snapshots.InsertAsync(scan.ScanId, record);

        var fileId = new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), null)
            .DeriveFileId(scan.ScanId);
        var file = new FileRecord(
            fileId, 1, "conf/app.json", null, null, 2,
            now, FileAttributes.Normal,
            new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), null),
            [AssetTypeId.Parse("ASSET-001")],
            InventoryStatus.Complete, "json", fileHash, CoverageStatus.Covered);
        await files.InsertAsync(scan.ScanId, file);

        var groupId = new FindingGroupId(Guid.NewGuid());
        var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "secret-value",
            "context",
            new SourceLocator.TextLocator(0, 0, 0, 12),
            "conf/app.json",
            fileHash,
            [new FindingProvenance(
                new DetectorId("DET-TEST"),
                new RuleId("RULE-TEST"),
                DetectionConfidence.High,
                false)]);
        var group = new FindingGroup(
            groupId, FindingKind.SensitiveContent, Severity.High,
            _fingerprint.Compute("secret-value"), [occurrence]);
        await findings.InsertGroupAsync(scan.ScanId, group);
        await findings.InsertOccurrenceAsync(file.FileId, occurrence);

        var query = new ScanQueryService(
            scans, findings, coverage, files,
            new StubReviewService(), snapshots, _protector);

        // Act
        OccurrenceFileLocation? location =
            await query.GetOccurrenceFileLocationAsync(
                scan.ScanId, occurrenceId);

        // Assert
        Assert.NotNull(location);
        Assert.Equal(Path.GetFullPath(realFile), location.AbsolutePath);
        Assert.True(location.FileExists);
        Assert.False(location.IsNested);

        // scanId isolation: another scan sees nothing.
        Assert.Null(await query.GetOccurrenceFileLocationAsync(
            new ScanId(Guid.NewGuid()), occurrenceId));
    }

    [Fact]
    public async Task Nested_occurrence_resolves_outer_container_path()
    {
        string root = Path.Combine(_tempDir, "rootC");
        Directory.CreateDirectory(root);
        string container = Path.Combine(root, "bundle.zip");
        await File.WriteAllBytesAsync(container, [1, 2, 3]);
        string fileHash = new string('c', 64);

        var scans = new SqliteScanRepository(_factory, _protector);
        var files = new SqliteFileRepository(_factory, _protector, _fingerprint);
        var findings = new SqliteFindingRepository(_factory, _protector, _fingerprint);
        var coverage = new SqliteCoverageRepository(_factory, _protector);
        var snapshots = new SqliteScanSnapshotRepository(_factory);

        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Completed, now, now,
            "rule-fp", "client-v1", "pipeline-hash",
            PlannedCount: 1, Version: 1);
        await scans.InsertAsync(scan);

        var codec = new ScanConfigurationSnapshotCodec(_protector);
        ScanConfigurationSnapshot snapshot = ScanSnapshotBuilder.Build(root);
        var record = new ScanSnapshotRecord(
            scan.ScanId,
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
            codec.Protect(scan.ScanId, snapshot));
        await snapshots.InsertAsync(scan.ScanId, record);

        var fileId = new FileStreamIdentity("VOL002", new UInt128(1, 2), null)
            .DeriveFileId(scan.ScanId);
        var file = new FileRecord(
            fileId, 0, "bundle.zip", null, null, 3,
            now, FileAttributes.Normal,
            new FileStreamIdentity("VOL002", new UInt128(1, 2), null),
            [AssetTypeId.Parse("ASSET-001")],
            InventoryStatus.Complete, "zip", fileHash, CoverageStatus.Covered);
        await files.InsertAsync(scan.ScanId, file);

        var groupId = new FindingGroupId(Guid.NewGuid());
        var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "secret-value",
            "context",
            new SourceLocator.NestedLocator(
                "bundle.zip",
                new SourceLocator.TextLocator(0, 0, 0, 12)),
            "bundle.zip!inner/secret.txt",
            fileHash,
            [new FindingProvenance(
                new DetectorId("DET-TEST"),
                new RuleId("RULE-TEST"),
                DetectionConfidence.High,
                false)]);
        var group = new FindingGroup(
            groupId, FindingKind.SensitiveContent, Severity.High,
            _fingerprint.Compute("secret-value"), [occurrence]);
        await findings.InsertGroupAsync(scan.ScanId, group);
        await findings.InsertOccurrenceAsync(file.FileId, occurrence);

        var query = new ScanQueryService(
            scans, findings, coverage, files,
            new StubReviewService(), snapshots, _protector);

        OccurrenceFileLocation? location =
            await query.GetOccurrenceFileLocationAsync(
                scan.ScanId, occurrenceId);

        Assert.NotNull(location);
        Assert.True(location.IsNested);
        Assert.Equal("bundle.zip", location.OuterVirtualPath);
        Assert.Equal(Path.GetFullPath(container), location.AbsolutePath);
        Assert.True(location.FileExists);
    }

    private static class ScanSnapshotBuilder
    {
        public static ScanConfigurationSnapshot Build(params string[] rootPaths) =>
            new(
                RootPaths: rootPaths,
                Manifest: new SecurityReview.Application.Scans.Preflight.ManifestSnapshot(
                    Manifest: null,
                    OriginalSha256: "manifest-hash",
                    Valid: true,
                    Errors: Array.Empty<SecurityReview.Application.Scans.Preflight.ManifestValidationError>()),
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
                Sandbox: new SecurityReview.Application.Scans.Preflight.SandboxSelfTestResult(
                    true, "ok", "worker-sha", "os-build", "profile-sid",
                    DateTimeOffset.UnixEpoch),
                EffectiveDetectorVersions: ["detector-v1"],
                CapturedAtUtc: DateTimeOffset.UnixEpoch);
    }

    private sealed class StubReviewService : SecurityReview.Application.Reviews.IReviewService
    {
        public Task<ReviewDecision> RecordReviewAsync(
            SecurityReview.Application.Reviews.RecordReviewCommand command,
            CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<ExceptionGrant> GrantExceptionAsync(
            SecurityReview.Application.Reviews.GrantExceptionCommand command,
            CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<SecurityReview.Application.Reviews.EffectiveReviewResult> GetEffectiveStatusAsync(
            FindingOccurrenceId occurrenceId,
            string assetBindingHmac,
            string occurrenceBindingHmac,
            CancellationToken ct = default)
            => Task.FromResult(new SecurityReview.Application.Reviews.EffectiveReviewResult(
                SecurityReview.Domain.Reviews.ReviewStatus.Pending, "pending", null));
    }

    public async ValueTask DisposeAsync()
    {
        _hkdf.Dispose();
        _protector.Dispose();
        _fingerprint.Dispose();

        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }

        await Task.CompletedTask;
    }
}
