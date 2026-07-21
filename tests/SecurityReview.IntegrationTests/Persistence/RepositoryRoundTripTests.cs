using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class RepositoryRoundTripTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public RepositoryRoundTripTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-roundtrip-").FullName;
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
    private SqliteFindingRepository CreateFindingRepo() => new(_factory, _protector, _fingerprint);
    private SqliteCoverageRepository CreateCoverageRepo() => new(_factory, _protector);
    private SqliteRulePackMetadataRepository CreateRulePackRepo() => new(_factory);

    [Fact]
    public async Task Insert_and_read_scan_round_trip()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Draft, now, now,
            "rule-fingerprint-abc", "client-v1.0", "pipeline-hash-xyz",
            PlannedCount: 42, Version: 1);

        await CreateScanRepo().InsertAsync(scan);

        var readBack = await CreateScanRepo().GetByIdAsync(scanId);
        Assert.NotNull(readBack);
        Assert.Equal(scanId, readBack.ScanId);
        Assert.Equal(ScanStatus.Draft, readBack.Status);
        Assert.Equal("rule-fingerprint-abc", readBack.RuleFingerprint);
        Assert.Equal("client-v1.0", readBack.ClientFingerprint);
        Assert.Equal("pipeline-hash-xyz", readBack.PipelineFingerprint);
        Assert.Equal(42L, readBack.PlannedCount);
        Assert.Equal(1L, readBack.Version);
    }

    [Fact]
    public async Task Insert_and_read_file_round_trip()
    {
        var scan = CreateScan();
        await CreateScanRepo().InsertAsync(scan);

        var file = CreateFileRecord(scan.ScanId);
        await CreateFileRepo().InsertAsync(scan.ScanId, file);

        var readBack = await CreateFileRepo().GetByIdAsync(file.FileId);
        Assert.NotNull(readBack);
        Assert.Equal(file.FileId, readBack.FileId);
        Assert.Equal(file.RelativePath, readBack.RelativePath);
        Assert.Equal(file.Length, readBack.Length);
        Assert.Equal(file.FormatId, readBack.FormatId);
        Assert.Equal(file.ContentSha256, readBack.ContentSha256);
        Assert.Equal(file.Coverage, readBack.Coverage);
    }

    [Fact]
    public async Task Insert_batch_and_read_files()
    {
        var scan = CreateScan();
        await CreateScanRepo().InsertAsync(scan);

        var files = Enumerable.Range(0, 5)
            .Select(i => CreateFileRecord(scan.ScanId, suffix: $"-{i}"))
            .ToList();

        await CreateFileRepo().InsertBatchAsync(scan.ScanId, files);

        var readBack = await CreateFileRepo().GetByScanIdAsync(scan.ScanId);
        Assert.Equal(5, readBack.Count);

        var count = await CreateFileRepo().CountByScanIdAsync(scan.ScanId);
        Assert.Equal(5, count);
    }

    [Fact]
    public async Task Insert_and_read_finding_group_with_occurrences()
    {
        // Insert prerequisite scan and file so occurrence references are valid.
        var scan = CreateScan();
        await CreateScanRepo().InsertAsync(scan);

        var file = CreateFileRecord(scan.ScanId);
        await CreateFileRepo().InsertAsync(scan.ScanId, file);

        var groupId = new FindingGroupId(Guid.NewGuid());
        var fingerprint = _fingerprint.Compute("test-secret-value");
        var occurrence = new FindingOccurrence(
            new FindingOccurrenceId(Guid.NewGuid()),
            groupId,
            "test-secret-value",
            "some context here",
            new SourceLocator.TextLocator(1, 5, 0, 20),
            "path/to/file.txt",
            "abc123",
            [new FindingProvenance(new DetectorId("DET-TEST"), new RuleId("RULE-TEST"), DetectionConfidence.High, false)]);

        var group = new FindingGroup(groupId, FindingKind.SensitiveContent, Severity.High, fingerprint,
            [occurrence]);

        await CreateFindingRepo().InsertGroupAsync(scan.ScanId, group);
        await CreateFindingRepo().InsertOccurrenceAsync(file.FileId, occurrence);

        var readBack = await CreateFindingRepo().GetGroupByIdAsync(groupId);
        Assert.NotNull(readBack);
        Assert.Equal(groupId, readBack.Id);
        Assert.Equal(FindingKind.SensitiveContent, readBack.FindingKind);
        Assert.Equal(Severity.High, readBack.Severity);
        Assert.Equal(fingerprint.HexString, readBack.ValueFingerprint.HexString);

        var occurrences = await CreateFindingRepo().GetOccurrencesByGroupIdAsync(groupId);
        Assert.Single(occurrences);
        Assert.Equal("test-secret-value", occurrences[0].RawValue);
        Assert.Single(occurrences[0].Provenance);
        Assert.Equal("DET-TEST", occurrences[0].Provenance[0].DetectorId.Value);
    }

    [Fact]
    public async Task Insert_and_read_coverage_gap()
    {
        var scan = CreateScan();
        await CreateScanRepo().InsertAsync(scan);

        var file = CreateFileRecord(scan.ScanId);
        await CreateFileRepo().InsertAsync(scan.ScanId, file);

        var gap = new CoverageGap(
            Guid.NewGuid(), scan.ScanId, file.FileId,
            "path/to/gap.txt", "text", "parsing",
            GapReason.UnsupportedFormat, "DETAIL-001",
            PlannedBytes: 1024, ProcessedBytes: 0,
            DateTimeOffset.UtcNow);

        await CreateCoverageRepo().InsertAsync(gap);

        var gaps = await CreateCoverageRepo().GetByScanIdAsync(scan.ScanId);
        Assert.Single(gaps);
        Assert.Equal(gap.GapId, gaps[0].GapId);
        Assert.Equal(GapReason.UnsupportedFormat, gaps[0].Reason);
        Assert.Equal("path/to/gap.txt", gaps[0].VirtualPath);
    }

    [Fact]
    public async Task Insert_and_read_rule_pack_metadata()
    {
        var rulePackHash = "abc123def456";
        var rulePackId = "RP-TEST";
        var version = "1.0.0";
        var signerId = "signer-test";
        var packagePathHmac = "hmac-value";
        var status = RulePackStatus.Imported;

        await CreateRulePackRepo().InsertAsync(
            rulePackHash, rulePackId, version, signerId, packagePathHmac, status);

        var readBack = await CreateRulePackRepo().GetByHashAsync(rulePackHash);
        Assert.NotNull(readBack);
        Assert.Equal(rulePackHash, readBack.Value.RulePackHash);
        Assert.Equal(rulePackId, readBack.Value.RulePackId);
        Assert.Equal(version, readBack.Value.Version);
        Assert.Equal(signerId, readBack.Value.SignerId);
        Assert.Equal(packagePathHmac, readBack.Value.PackagePathHmac);
        Assert.Equal(status, readBack.Value.Status);
    }

    [Fact]
    public async Task Encrypted_payload_does_not_contain_canary()
    {
        const string canary = "CANARY-abc123-xyz";
        var scan = CreateScan();
        await CreateScanRepo().InsertAsync(scan);

        var file = CreateFileRecord(scan.ScanId, relativePath: $"projects/{canary}/secret.txt");
        await CreateFileRepo().InsertAsync(scan.ScanId, file);

        await using var connection = await _factory.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT CAST(encrypted_payload AS TEXT) FROM file_records WHERE file_id = @id;";
        cmd.Parameters.AddWithValue("@id", file.FileId.Value.ToString("D"));

        var text = (await cmd.ExecuteScalarAsync())?.ToString() ?? "";
        Assert.DoesNotContain(canary, text, StringComparison.Ordinal);
    }

    private static ScanRun CreateScan()
    {
        var now = DateTimeOffset.UtcNow;
        return new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Draft, now, now,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 10, Version: 1);
    }

    private static FileRecord CreateFileRecord(
        ScanId scanId, string relativePath = "path/to/secret.txt", string? suffix = null)
    {
        var path = suffix is null ? relativePath : relativePath + suffix;
        var fileId = new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), suffix is null ? null : $"stream{suffix}")
            .DeriveFileId(scanId);
        return new FileRecord(
            fileId, 0, path, null, null, 1024,
            DateTimeOffset.UtcNow, FileAttributes.Normal,
            new FileStreamIdentity("VOL001", new UInt128(0x1234, 0x5678), suffix is null ? null : $"stream{suffix}"),
            [AssetTypeId.Parse("ASSET-001")],
            InventoryStatus.Complete, "text", "abc123def", CoverageStatus.Covered);
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
