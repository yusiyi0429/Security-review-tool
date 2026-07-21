using System.Security.Cryptography;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.History;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class ClearLocalDataTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly AppDataPaths _paths;
    private readonly SqliteScanRepository _scanRepo;

    public ClearLocalDataTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-clear-").FullName;
        _databasePath = Path.Combine(_tempDir, "Data", "securityreview.db");
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

        // Create dummy keyring file.
        File.WriteAllText(_paths.KeyRingFile, "dummy-keyring");
    }

    public async ValueTask DisposeAsync()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort */ }
        _protector.Dispose();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Denied_command_does_nothing()
    {
        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);
        var result = await service.ClearAsync(ClearLocalDataCommand.Denied);

        Assert.False(result.AllSucceeded);
        Assert.True(File.Exists(_databasePath)); // DB untouched.
        Assert.NotEqual("本工具本地数据已清除", result.UserMessage);
    }

    [Fact]
    public async Task Wrong_scan_count_is_rejected()
    {
        // Insert a scan.
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(scanId, ScanStatus.Completed, now, now,
            "hash", "v1", "pipe", 0, 1);
        await _scanRepo.InsertAsync(scan);

        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);

        // Claim wrong count.
        var result = await service.ClearAsync(new ClearLocalDataCommand(true, ScanCount: 0));

        Assert.False(result.AllSucceeded);
        Assert.True(File.Exists(_databasePath));
    }

    [Fact]
    public async Task Active_scan_blocks_clear()
    {
        // Insert an active scan.
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(scanId, ScanStatus.Running, now, now,
            "hash", "v1", "pipe", 0, 1);
        await _scanRepo.InsertAsync(scan);

        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);

        var result = await service.ClearAsync(new ClearLocalDataCommand(true, ScanCount: 1));

        Assert.False(result.AllSucceeded);
        Assert.True(File.Exists(_databasePath));
    }

    [Fact]
    public async Task Confirmed_clear_removes_database()
    {
        // Insert a completed scan.
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(scanId, ScanStatus.Completed, now, now,
            "hash", "v1", "pipe", 0, 1);
        await _scanRepo.InsertAsync(scan);

        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);

        var result = await service.ClearAsync(new ClearLocalDataCommand(true, ScanCount: 1));

        Assert.True(result.AllSucceeded);
        Assert.Equal("本工具本地数据已清除", result.UserMessage);
        Assert.False(File.Exists(_databasePath));
        Assert.False(File.Exists(_databasePath + "-wal"));

        // Directories should have been recreated (at least Data should exist).
        Assert.True(Directory.Exists(_paths.Data));
    }

    [Fact]
    public async Task Clear_removes_backups_and_temp()
    {
        // Create some backup and temp content.
        Directory.CreateDirectory(Path.Combine(_paths.Backups, "old-backup"));
        File.WriteAllText(Path.Combine(_paths.Backups, "old-backup", "backup.db"), "data");
        Directory.CreateDirectory(Path.Combine(_paths.Temp, "task-guid"));
        File.WriteAllText(Path.Combine(_paths.Temp, "task-guid", "temp.dat"), "temp");

        // Insert a completed scan.
        var scan = new ScanRun(new ScanId(Guid.NewGuid()), ScanStatus.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            "hash", "v1", "pipe", 0, 1);
        await _scanRepo.InsertAsync(scan);

        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);

        var result = await service.ClearAsync(new ClearLocalDataCommand(true, ScanCount: 1));

        Assert.True(result.AllSucceeded);
        Assert.False(Directory.Exists(Path.Combine(_paths.Backups, "old-backup")));
        Assert.False(Directory.Exists(Path.Combine(_paths.Temp, "task-guid")));
    }

    [Fact]
    public async Task Clear_with_no_scans_succeeds()
    {
        var service = new ClearLocalDataService(_scanRepo, _factory, _paths, null);

        var result = await service.ClearAsync(new ClearLocalDataCommand(true, ScanCount: 0));

        Assert.True(result.AllSucceeded);
        Assert.Equal("本工具本地数据已清除", result.UserMessage);
        Assert.False(File.Exists(_databasePath));
    }
}
