namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Creates on-demand database backups for operational safety.
/// Backups include the main database file and any WAL/SHM sidecar files.
/// </summary>
public sealed class DatabaseBackupService
{
    private readonly AppDataPaths _paths;
    private readonly ISqliteConnectionFactory _connectionFactory;

    public DatabaseBackupService(AppDataPaths paths, ISqliteConnectionFactory connectionFactory)
    {
        _paths = paths;
        _connectionFactory = connectionFactory;
    }

    /// <summary>
    /// Creates a full backup of the database to a timestamped directory
    /// under <c>Backups</c>. Checkpoints the WAL first so the backup is
    /// self-consistent. Returns the backup directory path, or <c>null</c>
    /// on failure.
    /// </summary>
    public string? CreateBackup()
    {
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToString(
                "yyyyMMddTHHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var backupDir = Path.Combine(_paths.Backups, $"manual_{timestamp}");
            Directory.CreateDirectory(backupDir);

            // Checkpoint WAL to consolidate.
            CheckpointWalSync();

            var dbPath = _paths.DatabaseFile;
            if (File.Exists(dbPath))
            {
                var destPath = Path.Combine(backupDir, Path.GetFileName(dbPath));
                File.Copy(dbPath, destPath, overwrite: false);
            }

            // Copy WAL and SHM sidecar files if present.
            CopySidecarIfExists(dbPath + "-wal", backupDir);
            CopySidecarIfExists(dbPath + "-shm", backupDir);

            return backupDir;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Creates a backup suitable for use before a destructive operation
    /// (e.g., clear-local-data). Returns the backup path or <c>null</c>.
    /// </summary>
    public string? CreatePreClearBackup()
    {
        try
        {
            var timestamp = DateTimeOffset.UtcNow.ToString(
                "yyyyMMddTHHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var backupDir = Path.Combine(_paths.Backups, $"pre_clear_{timestamp}");
            Directory.CreateDirectory(backupDir);

            CheckpointWalSync();

            var dbPath = _paths.DatabaseFile;
            if (File.Exists(dbPath))
            {
                var destPath = Path.Combine(backupDir, Path.GetFileName(dbPath));
                File.Copy(dbPath, destPath, overwrite: false);

                var keyringPath = _paths.KeyRingFile;
                if (File.Exists(keyringPath))
                {
                    File.Copy(keyringPath, Path.Combine(backupDir, Path.GetFileName(keyringPath)),
                        overwrite: false);
                }
            }

            CopySidecarIfExists(dbPath + "-wal", backupDir);
            CopySidecarIfExists(dbPath + "-shm", backupDir);

            return backupDir;
        }
        catch
        {
            return null;
        }
    }

    private void CheckpointWalSync()
    {
        try
        {
            using var connection = new Microsoft.Data.Sqlite.SqliteConnection(
                $"Data Source={_paths.DatabaseFile};Mode=ReadWrite;Pooling=false");
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.ExecuteNonQuery();
        }
        catch
        {
            // Non-fatal; backup proceeds without checkpoint.
        }
    }

    private static void CopySidecarIfExists(string sourcePath, string destDir)
    {
        if (File.Exists(sourcePath))
        {
            File.Copy(sourcePath,
                Path.Combine(destDir, Path.GetFileName(sourcePath)), overwrite: false);
        }
    }
}
