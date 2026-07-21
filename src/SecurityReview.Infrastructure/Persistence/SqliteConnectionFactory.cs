using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Creates and configures <see cref="SqliteConnection"/> instances with the
/// application's standard pragmas. Every opened connection enables foreign
/// keys, sets WAL journal mode, FULL synchronous, a 5-second busy timeout,
/// and in-memory temp store.
/// </summary>
public interface ISqliteConnectionFactory
{
    /// <summary>
    /// Opens a new connection and applies the standard pragma set.
    /// </summary>
    ValueTask<SqliteConnection> OpenAsync(CancellationToken cancellationToken = default);
}

public sealed class SqliteConnectionFactory : ISqliteConnectionFactory
{
    private readonly string _connectionString;

    public SqliteConnectionFactory(AppDataPaths paths)
    {
        var dbPath = paths.DatabaseFile;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 5,
        }.ToString();
    }

    /// <summary>
    /// Creates a factory with a custom database path — intended for testing.
    /// </summary>
    public SqliteConnectionFactory(string databasePath)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 5,
        }.ToString();
    }

    public async ValueTask<SqliteConnection> OpenAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        return connection;
    }
}
