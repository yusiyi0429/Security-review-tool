using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class RepositoryConcurrencyTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public RepositoryConcurrencyTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-concurrency-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        _hkdf = new HkdfSha256(masterKey);
        _protector = new AesGcmPayloadProtector(_hkdf.DeriveEncryptionKey(), "test-key");
        _fingerprint = new PersistentValueFingerprintService(_hkdf.DeriveFingerprintKey());

        // Create DB file and apply initial schema.
        using var init = new SqliteConnection($"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        new Migration001Initial().ApplyAsync(init, "test-integration", CancellationToken.None)
            .GetAwaiter().GetResult();
        init.Close();
    }

    private SqliteScanRepository CreateScanRepo() => new(_factory, _protector);
    private SqliteFileRepository CreateFileRepo() => new(_factory, _protector, _fingerprint);
    private SqliteCoverageRepository CreateCoverageRepo() => new(_factory, _protector);

    [Fact]
    public async Task TryTransition_concurrent_only_one_succeeds()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Draft, now, now,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 10, Version: 1);

        await CreateScanRepo().InsertAsync(scan);

        var task1 = Task.Run(() =>
            CreateScanRepo().TryTransitionAsync(scanId, ScanStatus.Draft, 1, ScanStatus.Preflight));
        var task2 = Task.Run(() =>
            CreateScanRepo().TryTransitionAsync(scanId, ScanStatus.Draft, 1, ScanStatus.Preflight));

        var results = await Task.WhenAll(task1, task2);
        var successCount = results.Count(r => r);

        Assert.Equal(1, successCount);
    }

    [Fact]
    public async Task TryTransition_wrong_version_fails()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Draft, now, now,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 10, Version: 1);

        await CreateScanRepo().InsertAsync(scan);

        var result = await CreateScanRepo().TryTransitionAsync(
            scanId, ScanStatus.Draft, expectedVersion: 2, ScanStatus.Preflight);

        Assert.False(result);
    }

    [Fact]
    public async Task TryTransition_wrong_status_fails()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Draft, now, now,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 10, Version: 1);

        await CreateScanRepo().InsertAsync(scan);

        var result = await CreateScanRepo().TryTransitionAsync(
            scanId, ScanStatus.Running, expectedVersion: 1, ScanStatus.Preflight);

        Assert.False(result);
    }

    [Fact]
    public async Task Foreign_key_violation_rolls_back()
    {
        var nonExistentScanId = new ScanId(Guid.NewGuid());
        var gap = new CoverageGap(
            Guid.NewGuid(), nonExistentScanId, FileId: null,
            "virtual/path.txt", "text", "parsing",
            GapReason.UnsupportedFormat, "DETAIL-FK",
            PlannedBytes: 100, ProcessedBytes: 0,
            DateTimeOffset.UtcNow);

        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => CreateCoverageRepo().InsertAsync(gap));

        Assert.NotNull(ex);

        // Verify the gap was NOT inserted.
        var gaps = await CreateCoverageRepo().GetByScanIdAsync(nonExistentScanId);
        Assert.Empty(gaps);
    }

    [Fact]
    public async Task Batch_insert_handles_large_set()
    {
        var scan = new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Draft,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 600, Version: 1);

        await CreateScanRepo().InsertAsync(scan);

        var files = new List<FileRecord>(600);
        for (int i = 0; i < 600; i++)
        {
            var fileId = new FileStreamIdentity("VOL001",
                new UInt128((ulong)(i / 1000), (ulong)(i % 1000)), StreamName: null)
                .DeriveFileId(scan.ScanId);
            files.Add(new FileRecord(
                fileId, 0, $"path/to/file-{i:D4}.txt", EncryptedPathPlaceholder: null,
                StreamName: null, Length: 1024 + i, DateTimeOffset.UtcNow,
                FileAttributes.Normal,
                new FileStreamIdentity("VOL001",
                    new UInt128((ulong)(i / 1000), (ulong)(i % 1000)), StreamName: null),
                ComponentAssetTypes: [AssetTypeId.Parse("ASSET-001")],
                InventoryStatus.Complete, FormatId: "text",
                ContentSha256: $"sha256-{i:D4}",
                CoverageStatus.NotCovered));
        }

        await CreateFileRepo().InsertBatchAsync(scan.ScanId, files);

        var count = await CreateFileRepo().CountByScanIdAsync(scan.ScanId);
        Assert.Equal(600, count);
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
    }
}
