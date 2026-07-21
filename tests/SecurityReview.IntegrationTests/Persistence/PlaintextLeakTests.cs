using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class PlaintextLeakTests : IAsyncDisposable
{
    private const string Canary = "PLAINTEXT-LEAK-CANARY-9f8a7b6c";

    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly string _backupDir;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public PlaintextLeakTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-leak-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _backupDir = Path.Combine(_tempDir, "backups");
        Directory.CreateDirectory(_backupDir);
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

    private SqliteFileRepository CreateFileRepo() => new(_factory, _protector, _fingerprint);
    private SqliteCoverageRepository CreateCoverageRepo() => new(_factory, _protector);

    [Fact]
    public async Task WAL_and_DB_contain_no_plaintext_canary()
    {
        var scan = CreateScan();
        var scanRepo = new SqliteScanRepository(_factory, _protector);
        await scanRepo.InsertAsync(scan);

        // Insert FileRecords with canary in encrypted path fields.
        for (int i = 0; i < 10; i++)
        {
            var file = CreateFileWithCanary(scan.ScanId, i);
            await CreateFileRepo().InsertAsync(scan.ScanId, file);
        }

        // Insert CoverageGaps with canary in encrypted path fields.
        for (int i = 0; i < 5; i++)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), scan.ScanId, FileId: null,
                $"{Canary}/gap-path-{i}", "text", "parsing",
                GapReason.UnsupportedFormat, "DETAIL-LEAK",
                PlannedBytes: 100 + i, ProcessedBytes: 0,
                DateTimeOffset.UtcNow);
            await CreateCoverageRepo().InsertAsync(gap);
        }

        // Checkpoint WAL to move everything into the main DB file.
        await using (var conn = await _factory.OpenAsync())
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            await cmd.ExecuteNonQueryAsync();
        }

        SqliteConnection.ClearAllPools();
        await Task.Delay(100);

        // Scan ALL files in temp dir for the canary in plaintext.
        var canaryBytes = Encoding.UTF8.GetBytes(Canary);
        foreach (var file in Directory.EnumerateFiles(_tempDir, "*", SearchOption.AllDirectories))
        {
            byte[] content = await File.ReadAllBytesAsync(file);
            if (IndexOfBytes(content, canaryBytes) >= 0)
                Assert.Fail($"Plaintext canary found in {file}");
        }

        // Also verify via raw SQL — encrypted_payload columns must never contain the canary.
        await using var verifyConn = await _factory.OpenAsync();
        await AssertNoCanaryInTable(verifyConn, "file_records", "encrypted_payload");
        await AssertNoCanaryInTable(verifyConn, "coverage_gaps", "encrypted_payload");
        await AssertNoCanaryInTable(verifyConn, "scan_runs", "encrypted_payload");
    }

    [Fact]
    public async Task Tampered_encrypted_payload_returns_error_not_plaintext()
    {
        var scan = CreateScan();
        var scanRepo = new SqliteScanRepository(_factory, _protector);
        await scanRepo.InsertAsync(scan);

        var file = CreateFileWithCanary(scan.ScanId, 0);
        await CreateFileRepo().InsertAsync(scan.ScanId, file);

        // Tamper with the encrypted payload: flip the last byte of the BLOB.
        await using (var conn = await _factory.OpenAsync())
        {
            await using var readCmd = conn.CreateCommand();
            readCmd.CommandText = "SELECT encrypted_payload FROM file_records WHERE file_id = @id;";
            readCmd.Parameters.AddWithValue("@id", file.FileId.Value.ToString("D"));
            var original = (byte[])(await readCmd.ExecuteScalarAsync())!;

            Assert.NotNull(original);
            Assert.NotEmpty(original);

            // Flip the last byte.
            var tampered = new byte[original.Length];
            original.CopyTo(tampered, 0);
            tampered[^1] = (byte)(tampered[^1] ^ 0xFF);

            await using var writeCmd = conn.CreateCommand();
            writeCmd.CommandText = "UPDATE file_records SET encrypted_payload = @payload WHERE file_id = @id;";
            writeCmd.Parameters.AddWithValue("@payload", tampered);
            writeCmd.Parameters.AddWithValue("@id", file.FileId.Value.ToString("D"));
            await writeCmd.ExecuteNonQueryAsync();
        }

        // Attempt to read back — must not return partial plaintext.
        Exception? caught = null;
        try
        {
            await CreateFileRepo().GetByIdAsync(file.FileId);
        }
        catch (Exception ex)
        {
            caught = ex;
        }

        Assert.NotNull(caught);

        // The exception message must NOT leak the canary.
        var message = caught.ToString();
        Assert.DoesNotContain(Canary, message, StringComparison.Ordinal);
    }

    private static async Task AssertNoCanaryInTable(
        SqliteConnection connection, string table, string column)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT CAST({column} AS TEXT) FROM {table} WHERE {column} IS NOT NULL;";
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var text = reader.GetString(0);
            Assert.DoesNotContain(Canary, text, StringComparison.Ordinal);
        }
    }

    private static int IndexOfBytes(byte[] haystack, byte[] needle)
    {
        int limit = haystack.Length - needle.Length;
        for (int i = 0; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match) return i;
        }

        return -1;
    }

    private static ScanRun CreateScan()
    {
        var now = DateTimeOffset.UtcNow;
        return new ScanRun(
            new ScanId(Guid.NewGuid()), ScanStatus.Draft, now, now,
            "rule-fingerprint", "client-v1", "pipeline-hash",
            PlannedCount: 50, Version: 1);
    }

    private static FileRecord CreateFileWithCanary(ScanId scanId, int index)
    {
        var fileId = new FileStreamIdentity("VOL001",
            new UInt128((ulong)(index / 1000), (ulong)(index % 1000)), StreamName: null)
            .DeriveFileId(scanId);
        return new FileRecord(
            fileId, 0, $"{Canary}/files/file-{index}.txt",
            EncryptedPathPlaceholder: null, StreamName: null,
            Length: 1024 + index, DateTimeOffset.UtcNow, FileAttributes.Normal,
            new FileStreamIdentity("VOL001",
                new UInt128((ulong)(index / 1000), (ulong)(index % 1000)), StreamName: null),
            ComponentAssetTypes: [AssetTypeId.Parse("ASSET-001")],
            InventoryStatus.Complete, FormatId: "text",
            ContentSha256: $"sha256-{index:D4}",
            CoverageStatus.NotCovered);
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
