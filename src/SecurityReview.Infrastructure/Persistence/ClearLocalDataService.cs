using SecurityReview.Application.Abstractions;
using SecurityReview.Application.History;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Irreversibly clears all local application data: database, backups,
/// cache, temp, diagnostics, rules, credentials, and the keyring.
/// Requires an explicit confirmation with the current scan count.
/// </summary>
public sealed class ClearLocalDataService
{
    private readonly IScanRepository _scanRepository;
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly IApplicationPaths _paths;
    private readonly ISecretStore? _secretStore;

    public ClearLocalDataService(
        IScanRepository scanRepository,
        ISqliteConnectionFactory connectionFactory,
        IApplicationPaths paths,
        ISecretStore? secretStore = null)
    {
        _scanRepository = scanRepository;
        _connectionFactory = connectionFactory;
        _paths = paths;
        _secretStore = secretStore;
    }

    /// <summary>
    /// Executes the clear-local-data operation. Requires
    /// <see cref="ClearLocalDataCommand.Confirmed"/> to be <c>true</c>
    /// and the scan count to match the current database state.
    /// </summary>
    public async Task<ClearLocalDataResult> ClearAsync(
        ClearLocalDataCommand command, CancellationToken cancellationToken = default)
    {
        // 1. Reject if not confirmed.
        if (!command.Confirmed)
            return DeniedResult(command.ScanCount);

        // 2. Verify scan count.
        var allScans = await _scanRepository.ListAsync(cancellationToken).ConfigureAwait(false);
        if (allScans.Count != command.ScanCount)
            return DeniedResult(allScans.Count);

        // 3. Stop if an active scan exists.
        if (HasActiveScanFromList(allScans))
            return DeniedResult(allScans.Count);

        // 4. Build the category map with initial status.
        var categories = new Dictionary<string, ClearCategoryStatus>
        {
            ["Database"] = ClearCategoryStatus.Skipped,
            ["Backups"] = ClearCategoryStatus.Skipped,
            ["Cache"] = ClearCategoryStatus.Skipped,
            ["Temp"] = ClearCategoryStatus.Skipped,
            ["Diagnostics"] = ClearCategoryStatus.Skipped,
            ["Rules"] = ClearCategoryStatus.Skipped,
            ["Credentials"] = ClearCategoryStatus.Skipped,
            ["Keyring"] = ClearCategoryStatus.Skipped,
        };

        // 5. Close connection pools so SQLite files can be deleted.
        _connectionFactory.ClearPools();

        // 6. Delete each category.
        DeleteCategory(categories, "Database", DeleteDatabaseFiles);
        DeleteCategory(categories, "Backups", () => DeleteDirectory(_paths.Backups));
        DeleteCategory(categories, "Temp", () => DeleteDirectory(_paths.Temp));
        DeleteCategory(categories, "Diagnostics", () => DeleteDirectory(_paths.Diagnostics));
        DeleteCategory(categories, "Rules", () => DeleteDirectory(_paths.Rules));
        DeleteCategory(categories, "Credentials", DeleteCredentials);
        DeleteCategory(categories, "Keyring", DeleteKeyring);

        // Cache is inline data in the DB — already handled by database deletion.
        categories["Cache"] = categories["Database"];

        // 7. Recreate empty base directories.
        try
        {
            _paths.EnsureCreated();
        }
        catch
        {
            // Directory creation failed — already recorded individual categories.
        }

        bool allSucceeded = categories.All(kv => kv.Value == ClearCategoryStatus.Succeeded);
        return new ClearLocalDataResult(allSucceeded, command.ScanCount, categories);
    }

    private static ClearLocalDataResult DeniedResult(int scanCount) =>
        new(false, scanCount, new Dictionary<string, ClearCategoryStatus>
        {
            ["Database"] = ClearCategoryStatus.Skipped,
            ["Backups"] = ClearCategoryStatus.Skipped,
            ["Cache"] = ClearCategoryStatus.Skipped,
            ["Temp"] = ClearCategoryStatus.Skipped,
            ["Diagnostics"] = ClearCategoryStatus.Skipped,
            ["Rules"] = ClearCategoryStatus.Skipped,
            ["Credentials"] = ClearCategoryStatus.Skipped,
            ["Keyring"] = ClearCategoryStatus.Skipped,
        });

    private static bool HasActiveScanFromList(IReadOnlyList<ScanRun> scans)
    {
        foreach (var scan in scans)
        {
            if (scan.Status is ScanStatus.Preflight
                or ScanStatus.Running
                or ScanStatus.Cancelling)
                return true;
        }
        return false;
    }

    private void DeleteDatabaseFiles()
    {
        var dbPath = _paths.DatabaseFile;
        DeleteFileIfExists(dbPath);
        DeleteFileIfExists(dbPath + "-wal");
        DeleteFileIfExists(dbPath + "-shm");
    }

    private void DeleteCredentials()
    {
        // DPAPI-protected secrets: deleting the key is cryptographic erasure.
        // The concrete ISecretStore handles the actual file deletion.
        if (_secretStore is not null)
        {
            try
            {
                // Delete the data key via the secret store.
                _secretStore.Delete("data-encryption-key");
            }
            catch
            {
                // Best-effort.
            }
        }

        // Also delete any remaining files in the Config directory.
        var configDir = _paths.Config;
        if (Directory.Exists(configDir))
        {
            try
            {
                foreach (var file in Directory.GetFiles(configDir))
                {
                    File.Delete(file);
                }
            }
            catch
            {
                // Best-effort.
            }
        }
    }

    private void DeleteKeyring()
    {
        var keyringPath = _paths.KeyRingFile;
        DeleteFileIfExists(keyringPath);
    }

    private static void DeleteCategory(
        Dictionary<string, ClearCategoryStatus> categories,
        string name,
        Action deleteAction)
    {
        try
        {
            deleteAction();
            categories[name] = ClearCategoryStatus.Succeeded;
        }
        catch
        {
            categories[name] = ClearCategoryStatus.Failed;
        }
    }

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }

    private static void DeleteFileIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
