using System.Security.Cryptography;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class StartupRecoveryTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly AppDataPaths _paths;
    private readonly SqliteScanRepository _scanRepo;

    public StartupRecoveryTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-recovery-").FullName;
        _databasePath = Path.Combine(_tempDir, "securityreview.db");
        _paths = AppDataPaths.CreateForTest(_tempDir);
        _paths.EnsureCreated();
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        var hkdf = new HkdfSha256(masterKey);
        _protector = new AesGcmPayloadProtector(hkdf.DeriveEncryptionKey(), "test-key");
        _scanRepo = new SqliteScanRepository(_factory, _protector);

        // Apply initial schema.
        using var init = new Microsoft.Data.Sqlite.SqliteConnection(
            $"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        new Migration001Initial().ApplyAsync(init, "test-integration", CancellationToken.None)
            .GetAwaiter().GetResult();
        init.Close();

        // Create a fake keyring file so keyring validation passes.
        File.WriteAllText(_paths.KeyRingFile, "dummy-keyring-content");
    }

    public async ValueTask DisposeAsync()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort */ }
        await CastAndDispose(_protector);
        return;

        static async ValueTask CastAndDispose(IDisposable d) { d.Dispose(); await Task.CompletedTask; }
    }

    private async Task<ScanRun> InsertScanAsync(ScanStatus status)
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, status, now, now,
            "rule-hash", "client-v1", "pipeline-hash",
            PlannedCount: 0, Version: 1);
        await _scanRepo.InsertAsync(scan);
        return scan;
    }

    [Fact]
    public async Task Recovers_interrupted_scans_to_interrupted_state()
    {
        var preflight = await InsertScanAsync(ScanStatus.Preflight);
        var running = await InsertScanAsync(ScanStatus.Running);
        var cancelling = await InsertScanAsync(ScanStatus.Cancelling);
        var completed = await InsertScanAsync(ScanStatus.Completed);

        var service = new StartupRecoveryService(_scanRepo, _factory, _paths);
        var result = await service.RecoverAsync();

        Assert.True(result.Success);
        Assert.Equal(3, result.InterruptedScans);
        Assert.Equal("OK", result.StatusCode);

        // Verify Preflight/Running/Cancelling → Interrupted
        var p = await _scanRepo.GetByIdAsync(preflight.ScanId);
        var r = await _scanRepo.GetByIdAsync(running.ScanId);
        var c = await _scanRepo.GetByIdAsync(cancelling.ScanId);

        Assert.Equal(ScanStatus.Interrupted, p!.Status);
        Assert.Equal(ScanStatus.Interrupted, r!.Status);
        Assert.Equal(ScanStatus.Interrupted, c!.Status);

        // Completed should remain unchanged.
        var co = await _scanRepo.GetByIdAsync(completed.ScanId);
        Assert.Equal(ScanStatus.Completed, co!.Status);
    }

    [Fact]
    public async Task Recovery_is_idempotent()
    {
        await InsertScanAsync(ScanStatus.Running);
        await InsertScanAsync(ScanStatus.Completed);

        var service = new StartupRecoveryService(_scanRepo, _factory, _paths);

        var first = await service.RecoverAsync();
        Assert.True(first.Success);
        Assert.Equal(1, first.InterruptedScans);

        var second = await service.RecoverAsync();
        Assert.True(second.Success);
        Assert.Equal(0, second.InterruptedScans); // Already interrupted, no-op.
    }

    [Fact]
    public async Task Health_check_failure_returns_error()
    {
        // Corrupt the database to trigger health check failure.
        await _scanRepo.InsertAsync(new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            "hash", "v1", "pipe", 0, 1));

        // Drop schema_versions table to cause health check failure.
        await using var conn = await _factory.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DROP TABLE IF EXISTS schema_versions;";
        await cmd.ExecuteNonQueryAsync();

        var service = new StartupRecoveryService(_scanRepo, _factory, _paths);
        var result = await service.RecoverAsync();

        Assert.False(result.Success);
        Assert.Equal("HEALTH_FAILED", result.StatusCode);
    }

    [Fact]
    public async Task Keyring_missing_returns_error()
    {
        // Remove the keyring file.
        File.Delete(_paths.KeyRingFile);

        var service = new StartupRecoveryService(_scanRepo, _factory, _paths);
        var result = await service.RecoverAsync();

        Assert.False(result.Success);
        Assert.Equal("KEYRING_MISSING", result.StatusCode);
    }
}
