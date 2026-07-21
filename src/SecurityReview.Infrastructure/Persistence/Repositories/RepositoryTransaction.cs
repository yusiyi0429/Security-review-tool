using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

/// <summary>
/// Wraps a <see cref="SqliteConnection"/> and a <see cref="SqliteTransaction"/>
/// opened on it. DisposeAsync automatically rolls back if the transaction was
/// not committed or rolled back explicitly.
/// </summary>
public sealed class RepositoryTransaction : IAsyncDisposable
{
    private bool _resolved;

    public SqliteConnection Connection { get; }
    public SqliteTransaction Transaction { get; }

    private RepositoryTransaction(SqliteConnection connection, SqliteTransaction transaction)
    {
        Connection = connection;
        Transaction = transaction;
    }

    public static async Task<RepositoryTransaction> BeginAsync(
        ISqliteConnectionFactory factory, CancellationToken ct = default)
    {
        var connection = await factory.OpenAsync(ct).ConfigureAwait(false);
        var transaction = connection.BeginTransaction();
        return new RepositoryTransaction(connection, transaction);
    }

    public Task CommitAsync(CancellationToken ct = default)
    {
        if (_resolved) return Task.CompletedTask;
        _resolved = true;
        Transaction.Commit();
        return Task.CompletedTask;
    }

    public Task RollbackAsync(CancellationToken ct = default)
    {
        if (_resolved) return Task.CompletedTask;
        _resolved = true;
        Transaction.Rollback();
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (!_resolved)
        {
            _resolved = true;
            Transaction.Rollback();
        }

        await Transaction.DisposeAsync().ConfigureAwait(false);
        await Connection.DisposeAsync().ConfigureAwait(false);
    }
}
