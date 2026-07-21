using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// A single forward-only schema migration. Each migration is applied
/// within a transaction and records its version in <c>schema_versions</c>
/// after successful DDL.
/// </summary>
public interface IMigration
{
    int Version { get; }
    Task ApplyAsync(SqliteConnection connection, string clientBuild, CancellationToken cancellationToken = default);
}
