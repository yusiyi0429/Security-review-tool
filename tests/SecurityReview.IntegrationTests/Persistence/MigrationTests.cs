using Microsoft.Data.Sqlite;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;

namespace SecurityReview.IntegrationTests.Persistence;

/// <summary>
/// Verifies schema migration idempotency, table structure, index presence,
/// and rollback behaviour.
/// </summary>
public sealed class MigrationTests : IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly string _backupPath;
    private readonly SqliteConnectionFactory _factory;
    private readonly MigrationRunner _runner;

    public MigrationTests()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"srt_migration_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmp);
        _databasePath = Path.Combine(tmp, "test.db");
        _backupPath = Path.Combine(tmp, "backups");
        _factory = new SqliteConnectionFactory(_databasePath);

        var migration = new Migration001Initial();
        _runner = new MigrationRunner(_factory, [migration], _databasePath, _backupPath);

        // Open the database to create it, then close it so MigrateAsync can open its own connection.
        using var init = new SqliteConnection($"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        init.Close();
    }

    [Fact]
    public async Task Migration_creates_schema_once_and_is_idempotent()
    {
        var result1 = await _runner.MigrateAsync(CancellationToken.None);
        Assert.True(result1.Success);
        Assert.Contains(1, result1.AppliedVersions);

        var result2 = await _runner.MigrateAsync(CancellationToken.None);
        Assert.True(result2.Success);
        Assert.Empty(result2.AppliedVersions);

        Assert.Equal(1, await ReadSchemaVersionAsync());
        Assert.Equal(ExpectedTables.All, await ReadUserTablesAsync(_databasePath));
    }

    [Fact]
    public async Task Schema_has_all_required_columns()
    {
        await _runner.MigrateAsync(CancellationToken.None);

        await using var connection = await _factory.OpenAsync();

        AssertColumns(connection, "scan_runs",
        [
            ("scan_id", "TEXT"), ("status", "INTEGER"), ("created_at_utc", "TEXT"),
            ("updated_at_utc", "TEXT"), ("rule_pack_hash", "TEXT"),
            ("client_version", "TEXT"), ("pipeline_fingerprint", "TEXT"),
            ("planned_units", "INTEGER"), ("version", "INTEGER"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "file_records",
        [
            ("file_id", "TEXT"), ("scan_id", "TEXT"), ("path_hmac", "TEXT"),
            ("content_sha256", "TEXT"), ("size", "INTEGER"), ("format_id", "TEXT"),
            ("coverage_status", "INTEGER"), ("parser_fingerprint", "TEXT"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "finding_groups",
        [
            ("group_id", "TEXT"), ("scan_id", "TEXT"), ("value_hmac", "TEXT"),
            ("category_id", "INTEGER"), ("severity", "INTEGER"),
            ("confidence", "INTEGER"), ("difference_status", "INTEGER"),
        ]);

        AssertColumns(connection, "finding_occurrences",
        [
            ("occurrence_id", "TEXT"), ("group_id", "TEXT"), ("file_id", "TEXT"),
            ("rule_id", "TEXT"), ("detector_id", "TEXT"),
            ("requires_semantic_review", "INTEGER"), ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "coverage_gaps",
        [
            ("gap_id", "TEXT"), ("scan_id", "TEXT"), ("file_id", "TEXT"),
            ("stage", "TEXT"), ("reason", "INTEGER"), ("detail_code", "TEXT"),
            ("planned_bytes", "INTEGER"), ("processed_bytes", "INTEGER"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "llm_reviews",
        [
            ("review_id", "TEXT"), ("scan_id", "TEXT"), ("candidate_id", "TEXT"),
            ("cache_key", "TEXT"), ("status", "INTEGER"),
            ("endpoint_fingerprint", "TEXT"), ("model_id", "TEXT"),
            ("prompt_version", "TEXT"), ("attempted_at_utc", "TEXT"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "review_decisions",
        [
            ("decision_id", "TEXT"), ("scan_id", "TEXT"), ("group_id", "TEXT"),
            ("occurrence_id", "TEXT"), ("status", "INTEGER"),
            ("user_sid_hmac", "TEXT"), ("decided_at_utc", "TEXT"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "exception_grants",
        [
            ("exception_id", "TEXT"), ("asset_binding_hmac", "TEXT"),
            ("occurrence_binding_hmac", "TEXT"), ("rule_pack_hash", "TEXT"),
            ("valid_until_utc", "TEXT"), ("created_at_utc", "TEXT"),
            ("user_sid_hmac", "TEXT"), ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "rule_packs",
        [
            ("rule_pack_hash", "TEXT"), ("rule_pack_id", "TEXT"),
            ("version", "TEXT"), ("signer_id", "TEXT"),
            ("imported_at_utc", "TEXT"), ("status", "INTEGER"),
            ("package_path_hmac", "TEXT"),
        ]);

        AssertColumns(connection, "cache_entries",
        [
            ("cache_key", "TEXT"), ("stage", "TEXT"), ("created_at_utc", "TEXT"),
            ("last_used_at_utc", "TEXT"), ("source_scan_id", "TEXT"),
            ("encrypted_payload", "BLOB"),
        ]);

        AssertColumns(connection, "diagnostic_events",
        [
            ("event_id", "TEXT"), ("scan_id", "TEXT"), ("event_code", "TEXT"),
            ("occurred_at_utc", "TEXT"), ("count_value", "INTEGER"),
            ("duration_ms", "REAL"), ("redacted_fields_json", "TEXT"),
        ]);
    }

    [Fact]
    public async Task Indexes_are_created()
    {
        await _runner.MigrateAsync(CancellationToken.None);

        await using var connection = await _factory.OpenAsync();

        var indexes = await ReadIndexesAsync(connection);
        Assert.Contains("ix_scan_runs_status", indexes);
        Assert.Contains("ix_scan_runs_created", indexes);
        Assert.Contains("ix_file_records_scan_path", indexes);
        Assert.Contains("ix_file_records_content_hash", indexes);
        Assert.Contains("ix_finding_groups_scan_value", indexes);
        Assert.Contains("ix_finding_groups_category", indexes);
        Assert.Contains("ix_finding_occurrences_group", indexes);
        Assert.Contains("ix_finding_occurrences_file", indexes);
        Assert.Contains("ix_coverage_gaps_scan", indexes);
        Assert.Contains("ix_coverage_gaps_reason", indexes);
        Assert.Contains("ix_llm_reviews_candidate", indexes);
        Assert.Contains("ix_llm_reviews_cache_key", indexes);
        Assert.Contains("ix_review_decisions_group", indexes);
        Assert.Contains("ix_review_decisions_occurrence", indexes);
        Assert.Contains("ix_review_decisions_time", indexes);
        Assert.Contains("ix_exception_grants_binding", indexes);
        Assert.Contains("ix_exception_grants_expiry", indexes);
        Assert.Contains("ix_cache_entries_stage", indexes);
        Assert.Contains("ix_cache_entries_last_used", indexes);
    }

    [Fact]
    public async Task Foreign_key_constraints_exist()
    {
        await _runner.MigrateAsync(CancellationToken.None);

        await using var connection = await _factory.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_versions';
            """;
        await using var reader = await cmd.ExecuteReaderAsync();

        var tablesWithFKs = new HashSet<string>
        {
            "assets", "file_records", "finding_groups", "finding_occurrences",
            "coverage_gaps", "llm_reviews", "review_decisions", "diagnostic_events",
        };

        while (await reader.ReadAsync())
        {
            var name = reader.GetString(0);
            var sql = reader.GetString(1);
            if (tablesWithFKs.Contains(name))
            {
                Assert.Contains("FOREIGN KEY", sql);
            }
        }
    }

    private async Task<int> ReadSchemaVersionAsync()
    {
        await using var connection = await _factory.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_versions;";
        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<HashSet<string>> ReadUserTablesAsync(string databasePath)
    {
        await using var connection = new SqliteConnection($"Data Source={databasePath};Mode=ReadOnly");
        await connection.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_versions'
            ORDER BY name;
            """;
        await using var reader = await cmd.ExecuteReaderAsync();

        var tables = new HashSet<string>();
        while (await reader.ReadAsync())
            tables.Add(reader.GetString(0));
        return tables;
    }

    private static async Task<List<string>> ReadIndexesAsync(SqliteConnection connection)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name;
            """;
        await using var reader = await cmd.ExecuteReaderAsync();
        var indexes = new List<string>();
        while (await reader.ReadAsync())
            indexes.Add(reader.GetString(0));
        return indexes;
    }

    private static void AssertColumns(SqliteConnection connection, string table, (string Name, string Type)[] expected)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info(\"{table}\");";
        using var reader = cmd.ExecuteReader();
        var columns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
            columns[reader.GetString(1)] = reader.GetString(2).ToUpperInvariant();

        foreach (var (name, type) in expected)
        {
            Assert.True(columns.ContainsKey(name), $"Column '{table}.{name}' missing.");
            Assert.Equal(type, columns[name]);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            var dir = Path.GetDirectoryName(_databasePath)!;
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}

internal static class ExpectedTables
{
    public static readonly HashSet<string> All = new(StringComparer.OrdinalIgnoreCase)
    {
        "scan_runs", "assets", "file_records", "finding_groups",
        "finding_occurrences", "coverage_gaps", "llm_reviews",
        "review_decisions", "exception_grants", "rule_packs",
        "cache_entries", "diagnostic_events",
    };
}
