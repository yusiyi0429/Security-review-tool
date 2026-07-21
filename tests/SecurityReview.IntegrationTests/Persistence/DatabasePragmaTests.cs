using Microsoft.Data.Sqlite;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.IntegrationTests.Persistence;

/// <summary>
/// Verifies that every connection opened through <see cref="SqliteConnectionFactory"/>
/// has the required pragmas applied.
/// </summary>
public sealed class DatabasePragmaTests : IAsyncDisposable
{
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;

    public DatabasePragmaTests()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"srt_pragma_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmp);
        _databasePath = Path.Combine(tmp, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);
    }

    [Fact]
    public async Task Connection_enables_required_pragmas()
    {
        await using var connection = await _factory.OpenAsync(CancellationToken.None);

        Assert.Equal(1L, await ScalarAsync<long>(connection, "PRAGMA foreign_keys;"));
        Assert.Equal("wal", (await ScalarAsync<string>(connection, "PRAGMA journal_mode;")).ToLowerInvariant());
        Assert.True(await ScalarAsync<long>(connection, "PRAGMA busy_timeout;") >= 5000);
    }

    [Fact]
    public async Task Connection_synchronous_is_full()
    {
        await using var connection = await _factory.OpenAsync(CancellationToken.None);
        Assert.Equal(2L, await ScalarAsync<long>(connection, "PRAGMA synchronous;"));
    }

    [Fact]
    public async Task Connection_temp_store_is_memory()
    {
        await using var connection = await _factory.OpenAsync(CancellationToken.None);
        Assert.Equal(2L, await ScalarAsync<long>(connection, "PRAGMA temp_store;"));
    }

    [Fact]
    public async Task Multiple_connections_all_have_pragmas()
    {
        await using var c1 = await _factory.OpenAsync(CancellationToken.None);
        await using var c2 = await _factory.OpenAsync(CancellationToken.None);

        Assert.Equal(1L, await ScalarAsync<long>(c1, "PRAGMA foreign_keys;"));
        Assert.Equal(1L, await ScalarAsync<long>(c2, "PRAGMA foreign_keys;"));
    }

    private static async Task<T> ScalarAsync<T>(SqliteConnection connection, string sql)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        var result = await cmd.ExecuteScalarAsync();
        return (T)Convert.ChangeType(result!, typeof(T), System.Globalization.CultureInfo.InvariantCulture);
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
