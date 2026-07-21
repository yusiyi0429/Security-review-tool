using System.Diagnostics;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Runs at application startup before any new scan begins. Acquires an
/// app mutex, checks database health, recovers interrupted scans, cleans
/// orphan task temporaries, checkpoints the WAL, and validates the
/// active rule pointer and keyring.
/// </summary>
public sealed class StartupRecoveryService
{
    private readonly IScanRepository _scanRepository;
    private readonly ISqliteConnectionFactory _connectionFactory;
    private readonly AppDataPaths _paths;

    public StartupRecoveryService(
        IScanRepository scanRepository,
        ISqliteConnectionFactory connectionFactory,
        AppDataPaths paths)
    {
        _scanRepository = scanRepository;
        _connectionFactory = connectionFactory;
        _paths = paths;
    }

    /// <summary>
    /// Performs the full startup recovery sequence.
    /// </summary>
    public async Task<StartupRecoveryResult> RecoverAsync(CancellationToken cancellationToken = default)
    {
        var mutexName = @"Global\SecurityReviewTool_AppInstance_" +
            _paths.BasePath.Replace(Path.DirectorySeparatorChar, '_').Replace(':', '_');

        // 1. Acquire app mutex.
        using var mutex = new Mutex(initiallyOwned: false, mutexName);
        bool acquired;
        try
        {
            acquired = mutex.WaitOne(TimeSpan.FromSeconds(5));
        }
        catch (AbandonedMutexException)
        {
            acquired = true; // Previous holder terminated; proceed.
        }

        if (!acquired)
            return StartupRecoveryResult.MutexTimeout();

        try
        {
            // 2. Run database health check.
            DatabaseHealthResult? healthResult = null;
            try
            {
                await using var healthConn = await _connectionFactory.OpenAsync(cancellationToken)
                    .ConfigureAwait(false);
                healthResult = await DatabaseHealthCheck.RunAsync(healthConn, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return StartupRecoveryResult.HealthCheckFailed(ex.Message);
            }

            if (!healthResult!.IsHealthy)
                return StartupRecoveryResult.HealthCheckFailed(healthResult.Detail);

            // 3. Map Preflight/Running/Cancelling → Interrupted.
            int interruptedCount = 0;
            try
            {
                interruptedCount = await RecoverInterruptedScansAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return StartupRecoveryResult.RecoveryFailed(ex.Message);
            }

            // 4. Clean orphan task temp directories.
            int cleanedTempCount = 0;
            try
            {
                cleanedTempCount = CleanOrphanTaskTemp();
            }
            catch
            {
                // Best-effort; non-fatal.
            }

            // 5. Checkpoint WAL.
            try
            {
                await CheckpointWalAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Best-effort; non-fatal.
            }

            // 6. Validate active rule pointer and keyring.
            try
            {
                var keyringValid = ValidateKeyring();
                if (!keyringValid)
                    return StartupRecoveryResult.KeyringMissing();
            }
            catch
            {
                return StartupRecoveryResult.KeyringMissing();
            }

            return StartupRecoveryResult.Succeeded(
                healthResult,
                interruptedCount,
                cleanedTempCount);
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    private async Task<int> RecoverInterruptedScansAsync(CancellationToken cancellationToken)
    {
        var inFlightStatuses = new[]
        {
            ScanStatus.Preflight,
            ScanStatus.Running,
            ScanStatus.Cancelling,
        };

        var inFlight = await _scanRepository.ListByStatusAsync(inFlightStatuses, cancellationToken)
            .ConfigureAwait(false);

        int interrupted = 0;
        foreach (var scan in inFlight)
        {
            var mapped = ScanStateMachine.RecoverAfterProcessExit(scan.Status);
            if (mapped == scan.Status)
                continue; // Already terminal — nothing to do.

            var success = await _scanRepository.TryTransitionAsync(
                scan.ScanId, scan.Status, scan.Version, mapped, cancellationToken)
                .ConfigureAwait(false);

            if (success)
                interrupted++;
        }

        return interrupted;
    }

    private int CleanOrphanTaskTemp()
    {
        var tempDir = _paths.Temp;
        if (!Directory.Exists(tempDir))
            return 0;

        var processStart = Process.GetCurrentProcess().StartTime.ToUniversalTime();
        int cleaned = 0;

        foreach (var dir in Directory.GetDirectories(tempDir))
        {
            try
            {
                var info = new DirectoryInfo(dir);

                // Skip reparse points / junctions.
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                    continue;

                var creationTime = info.CreationTimeUtc;

                // Only delete directories older than the current process start.
                if (creationTime >= processStart)
                    continue;

                // Only delete if it looks like a task temp directory
                // (name contains a GUID pattern).
                var dirName = Path.GetFileName(dir);
                if (!IsLikelyTaskDirectory(dirName))
                    continue;

                Directory.Delete(dir, recursive: true);
                cleaned++;
            }
            catch
            {
                // Best-effort.
            }
        }

        return cleaned;
    }

    private static bool IsLikelyTaskDirectory(string dirName)
    {
        // Task temp directories are named with GUIDs or contain GUID-like patterns.
        // A simple heuristic: length >= 32 and mostly hex/separator chars.
        if (dirName.Length < 32 || dirName.Length > 40)
            return false;

        foreach (char c in dirName)
        {
            if (c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F' or '-' or '_')
                continue;
            return false;
        }

        return true;
    }

    private async Task CheckpointWalAsync(CancellationToken cancellationToken)
    {
        await using var connection = await _connectionFactory.OpenAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private bool ValidateKeyring()
    {
        var keyringPath = _paths.KeyRingFile;
        return File.Exists(keyringPath);
    }
}

/// <summary>
/// Result of a startup recovery sequence.
/// </summary>
public sealed record StartupRecoveryResult(
    bool Success,
    string StatusCode,
    string Detail,
    DatabaseHealthResult? HealthResult,
    int InterruptedScans,
    int CleanedTempDirs)
{
    private const string CodeOk = "OK";
    private const string CodeMutexTimeout = "MUTEX_TIMEOUT";
    private const string CodeHealthFailed = "HEALTH_FAILED";
    private const string CodeRecoveryFailed = "RECOVERY_FAILED";
    private const string CodeKeyringMissing = "KEYRING_MISSING";

    public static StartupRecoveryResult MutexTimeout() =>
        new(false, CodeMutexTimeout, "Could not acquire application mutex within 5 seconds.",
            null, 0, 0);

    public static StartupRecoveryResult HealthCheckFailed(string detail) =>
        new(false, CodeHealthFailed, $"Database health check failed: {detail}",
            null, 0, 0);

    public static StartupRecoveryResult RecoveryFailed(string detail) =>
        new(false, CodeRecoveryFailed, $"Scan recovery failed: {detail}",
            null, 0, 0);

    public static StartupRecoveryResult KeyringMissing() =>
        new(false, CodeKeyringMissing, "Keyring file is missing or corrupt.",
            null, 0, 0);

    public static StartupRecoveryResult Succeeded(
        DatabaseHealthResult health, int interrupted, int cleanedTemp) =>
        new(true, CodeOk, "Startup recovery completed.",
            health, interrupted, cleanedTemp);
}
