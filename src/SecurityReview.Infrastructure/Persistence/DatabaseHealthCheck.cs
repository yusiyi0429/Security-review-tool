using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Result of a database health check. <see cref="IsHealthy"/> is
/// <c>true</c> only when all checks pass.
/// </summary>
public sealed record DatabaseHealthResult(bool IsHealthy, string Detail)
{
    public static DatabaseHealthResult Ok() => new(true, "OK");
    public static DatabaseHealthResult Fail(string detail) => new(false, detail);
}

/// <summary>
/// Runs a set of health checks against an open SQLite connection:
/// PRAGMA quick_check, schema version compatibility, foreign key
/// enforcement, and a write/delete canary transaction.
/// </summary>
public static class DatabaseHealthCheck
{
    /// <summary>
    /// Runs all health checks. Returns a result with a stable status code.
    /// </summary>
    public static async Task<DatabaseHealthResult> RunAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken = default)
    {
        // 1. PRAGMA quick_check
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA quick_check;";
        var quickCheck = (await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))?.ToString();
        if (quickCheck != "ok")
            return DatabaseHealthResult.Fail($"quick_check: {quickCheck}");

        // 2. Schema version compatible.
        cmd.CommandText = """
            SELECT version FROM schema_versions ORDER BY version DESC LIMIT 1;
            """;
        try
        {
            var version = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (version is not long schemaVersion || schemaVersion < 1)
                return DatabaseHealthResult.Fail("Schema version missing or invalid.");
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 1) // SQLITE_ERROR — table missing
        {
            return DatabaseHealthResult.Fail("Schema version table missing.");
        }

        // 3. Foreign key enforcement check.
        cmd.CommandText = "PRAGMA foreign_keys;";
        var fkResult = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (fkResult is not long fkOn || fkOn != 1)
            return DatabaseHealthResult.Fail("Foreign keys not enforced.");

        // 4. Write/delete canary transaction.
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS _health_canary (id INTEGER PRIMARY KEY, value TEXT);
                INSERT INTO _health_canary (id, value) VALUES (1, 'canary');
                DELETE FROM _health_canary WHERE id = 1;
                DROP TABLE IF EXISTS _health_canary;
                """;
            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return DatabaseHealthResult.Fail("Write/delete canary failed.");
        }

        return DatabaseHealthResult.Ok();
    }
}
