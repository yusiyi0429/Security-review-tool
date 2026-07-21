using System.Reflection;
using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// Runs forward-only schema migrations against a SQLite database.
/// Acquires a named mutex per database path, checkpoints the WAL,
/// backs up the database before any version increase, applies each
/// migration in its own transaction, and records schema versions.
/// On failure the database is left intact and a read-only-history
/// result is returned.
/// </summary>
public sealed class MigrationRunner
{
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly IReadOnlyList<IMigration> _migrations;
    private readonly string _databasePath;
    private readonly string _backupBasePath;

    public MigrationRunner(
        ISqliteConnectionFactory connectionFactory,
        IReadOnlyList<IMigration> migrations,
        AppDataPaths paths)
        : this(connectionFactory, migrations, paths.DatabaseFile, paths.Backups)
    {
    }

    public MigrationRunner(
        ISqliteConnectionFactory connectionFactory,
        IReadOnlyList<IMigration> migrations,
        string databasePath,
        string backupBasePath)
    {
        _connectionFactory = connectionFactory;
        _migrations = migrations;
        _databasePath = databasePath;
        _backupBasePath = backupBasePath;
    }

    /// <summary>
    /// Returns the client build string recorded in schema_versions.
    /// Derived from the entry assembly's informational version.
    /// </summary>
    public static string ClientBuild =>
        Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
        ?? "0.0.0";

    /// <summary>
    /// Applies all pending migrations. The database schema must already
    /// exist (created by opening a connection). This method is idempotent:
    /// migrations already recorded in schema_versions are skipped.
    /// </summary>
    public async Task<MigrationResult> MigrateAsync(CancellationToken cancellationToken = default)
    {
        // Acquire per-database-path named mutex.
        var mutexName = @"Global\SecurityReviewTool_DBMigrate_" + _databasePath.Replace(Path.DirectorySeparatorChar, '_').Replace(':', '_');
        using var mutex = new Mutex(initiallyOwned: false, mutexName);

        try
        {
            if (!mutex.WaitOne(TimeSpan.FromSeconds(30)))
                return MigrationResult.Timeout(mutexName);
        }
        catch (AbandonedMutexException)
        {
            // Previous holder terminated without releasing; proceed.
        }

        try
        {
            await using var connection = await _connectionFactory.OpenAsync(cancellationToken).ConfigureAwait(false);

            // Checkpoint WAL before migrating.
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            // Determine current schema version (0 if no schema_versions table).
            var currentVersion = await ReadCurrentVersionAsync(connection, cancellationToken).ConfigureAwait(false);

            if (currentVersion < 0)
            {
                // Table exists but no version rows — something is wrong.
                return MigrationResult.CorruptSchema();
            }

            // Find pending migrations.
            var pending = _migrations
                .Where(m => m.Version > currentVersion)
                .OrderBy(m => m.Version)
                .ToList();

            if (pending.Count == 0)
                return MigrationResult.NoOp(currentVersion);

            // Create backup before version increase.
            string? backupPath = null;
            if (currentVersion > 0)
            {
                backupPath = CreateBackup(currentVersion);
                if (backupPath is null)
                    return MigrationResult.BackupFailed();
            }

            var appliedVersions = new List<int>();

            foreach (var migration in pending)
            {
                await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

                try
                {
                    await migration.ApplyAsync(connection, ClientBuild, cancellationToken).ConfigureAwait(false);
                    await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
                    appliedVersions.Add(migration.Version);
                }
                catch (Exception ex)
                {
                    await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                    return MigrationResult.Failed(
                        migration.Version,
                        ex,
                        appliedVersions,
                        backupPath);
                }
            }

            // Run health check after migration.
            var health = await DatabaseHealthCheck.RunAsync(connection, cancellationToken).ConfigureAwait(false);
            if (!health.IsHealthy)
            {
                return MigrationResult.HealthCheckFailed(health, appliedVersions, backupPath);
            }

            // Delete backup after successful migration + health check.
            if (backupPath is not null)
            {
                try
                {
                    var backupDir = Path.GetDirectoryName(backupPath)!;
                    if (Directory.Exists(backupDir))
                        Directory.Delete(backupDir, recursive: true);
                }
                catch
                {
                    // Best-effort cleanup; non-fatal.
                }
            }

            return MigrationResult.Succeeded(appliedVersions);
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    /// <summary>
    /// Reads the highest schema version from schema_versions.
    /// Returns 0 if the table does not exist, -1 if corrupt.
    /// </summary>
    private static async Task<int> ReadCurrentVersionAsync(
        SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var cmd = connection.CreateCommand();

        // Check if schema_versions table exists.
        cmd.CommandText = """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type = 'table' AND name = 'schema_versions';
            """;
        var tableCount = (long)(await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;

        if (tableCount == 0)
            return 0;

        cmd.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_versions;";
        var maxVersion = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return maxVersion is long l ? (int)l : -1;
    }

    private string CreateBackup(int currentVersion)
    {
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var backupDir = Path.Combine(_backupBasePath, $"v{currentVersion}_pre_migration_{timestamp}");
            Directory.CreateDirectory(backupDir);

            var dbFile = new FileInfo(_databasePath);
            if (dbFile.Exists)
            {
                File.Copy(_databasePath, Path.Combine(backupDir, dbFile.Name), overwrite: false);
            }

            // Copy WAL and SHM files if present.
            CopyIfExists(_databasePath + "-wal", backupDir);
            CopyIfExists(_databasePath + "-shm", backupDir);

            return backupDir;
        }
        catch
        {
            return null!; // string? is nullable; null signals failure.
        }

        static void CopyIfExists(string sourcePath, string destDir)
        {
            if (File.Exists(sourcePath))
            {
                File.Copy(sourcePath, Path.Combine(destDir, Path.GetFileName(sourcePath)), overwrite: false);
            }
        }
    }
}

public sealed record MigrationResult(
    bool Success,
    IReadOnlyList<int> AppliedVersions,
    string? ErrorMessage,
    string? BackupPath,
    bool ReadOnlyHistory)
{
    public static MigrationResult NoOp(int currentVersion) =>
        new(true, Array.Empty<int>(), null, null, ReadOnlyHistory: false);

    public static MigrationResult Succeeded(IReadOnlyList<int> versions) =>
        new(true, versions, null, null, ReadOnlyHistory: false);

    public static MigrationResult Timeout(string mutexName) =>
        new(false, Array.Empty<int>(), $"Migration mutex timeout: {mutexName}", null, ReadOnlyHistory: true);

    public static MigrationResult CorruptSchema() =>
        new(false, Array.Empty<int>(), "Schema version table is corrupt.", null, ReadOnlyHistory: true);

    public static MigrationResult BackupFailed() =>
        new(false, Array.Empty<int>(), "Pre-migration backup failed.", null, ReadOnlyHistory: false);

    public static MigrationResult Failed(
        int version, Exception ex, IReadOnlyList<int> appliedVersions, string? backupPath) =>
        new(false, appliedVersions, $"Migration v{version} failed: {ex.Message}", backupPath, ReadOnlyHistory: true);

    public static MigrationResult HealthCheckFailed(
        DatabaseHealthResult health, IReadOnlyList<int> appliedVersions, string? backupPath) =>
        new(false, appliedVersions, $"Health check failed after migration: {health.Detail}", backupPath, ReadOnlyHistory: true);
}
