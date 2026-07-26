using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Persistence;

public sealed class SqliteMaintenanceServiceTests : IAsyncDisposable
{
    private readonly string _tempDirectory;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;

    public SqliteMaintenanceServiceTests()
    {
        _tempDirectory = Path.Combine(
            Path.GetTempPath(),
            "srt-maintenance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDirectory);
        _databasePath = Path.Combine(_tempDirectory, "maintenance.db");
        _factory = new SqliteConnectionFactory(_databasePath);
    }

    [Fact]
    public async Task DeleteExpiredScans_executes_cascade_inside_one_transaction()
    {
        var migrations = new MigrationRunner(
            _factory,
            DefaultMigrations.Create(),
            _databasePath,
            Path.Combine(_tempDirectory, "backups"));
        MigrationResult migration = await migrations.MigrateAsync();
        Assert.True(migration.Success);

        var scans = new SqliteScanRepository(
            _factory,
            new PassthroughPayloadProtector());
        var scanId = new ScanId(Guid.NewGuid());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await scans.InsertAsync(new ScanRun(
            scanId,
            ScanStatus.Completed,
            now,
            now,
            "rule",
            "client",
            "pipeline",
            0,
            1));
        await InsertFindingGraphAsync(scanId);

        var maintenance = new SqliteMaintenanceService(_factory);
        int deleted = await maintenance.DeleteExpiredScansAsync([scanId]);

        Assert.Equal(1, deleted);
        Assert.Null(await scans.GetByIdAsync(scanId));
        Assert.Equal(0, await CountRowsAsync("finding_occurrences"));
        Assert.Equal(0, await CountRowsAsync("finding_groups"));
        Assert.Equal(0, await CountRowsAsync("file_records"));
        Assert.Equal(0, await CountRowsAsync("review_decisions"));
    }

    private async Task InsertFindingGraphAsync(ScanId scanId)
    {
        string fileId = Guid.NewGuid().ToString();
        string groupId = Guid.NewGuid().ToString();
        string occurrenceId = Guid.NewGuid().ToString();
        await using var connection = await _factory.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO file_records (
                file_id, scan_id, path_hmac, coverage_status)
            VALUES (@fileId, @scanId, 'path', 0);

            INSERT INTO finding_groups (
                group_id, scan_id, value_hmac, category_id, severity,
                confidence, difference_status)
            VALUES (@groupId, @scanId, 'value', 0, 0, 0, 0);

            INSERT INTO finding_occurrences (
                occurrence_id, group_id, file_id, rule_id, detector_id,
                requires_semantic_review)
            VALUES (@occurrenceId, @groupId, @fileId, 'rule', 'detector', 0);

            INSERT INTO review_decisions (
                decision_id, scan_id, group_id, occurrence_id, status,
                user_sid_hmac, decided_at_utc)
            VALUES (
                @decisionId, @scanId, @groupId, @occurrenceId, 0,
                'user', @decidedAt);
            """;
        command.Parameters.AddWithValue("@fileId", fileId);
        command.Parameters.AddWithValue("@groupId", groupId);
        command.Parameters.AddWithValue("@occurrenceId", occurrenceId);
        command.Parameters.AddWithValue("@decisionId", Guid.NewGuid().ToString());
        command.Parameters.AddWithValue("@scanId", scanId.Value.ToString());
        command.Parameters.AddWithValue("@decidedAt", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> CountRowsAsync(string table)
    {
        await using var connection = await _factory.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table};";
        return (long)(await command.ExecuteScalarAsync() ?? 0L);
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            Directory.Delete(_tempDirectory, recursive: true);
        }
        catch
        {
            // Best effort cleanup for locked Windows test files.
        }

        return ValueTask.CompletedTask;
    }

    private sealed class PassthroughPayloadProtector : IPayloadProtector
    {
        public EncryptedPayload Protect(
            string table,
            string recordId,
            string fieldName,
            byte[] plaintext) =>
            new(
                Version: 1,
                KeyId: "test",
                NonceBase64: string.Empty,
                CiphertextBase64: Convert.ToBase64String(plaintext),
                TagBase64: string.Empty);

        public byte[] Unprotect(
            string table,
            string recordId,
            string fieldName,
            EncryptedPayload payload) =>
            Convert.FromBase64String(payload.CiphertextBase64);
    }
}
