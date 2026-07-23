using System.Text.Json;
using System.Security.Cryptography;
using SecurityReview.Application.Rules;
using SecurityReview.RulePack.Packaging;

namespace SecurityReview.Infrastructure.Rules;

/// <summary>
/// File-system-backed <see cref="IRulePackStore"/> rooted at
/// <c>%LOCALAPPDATA%\SecurityReviewTool\rules</c>.
///
/// Packages are stored immutably under <c>packages/{rulePackId}/{version}/{sha256}.zip</c>
/// and are read-only after placement. The active pointer is a small
/// <c>active.json</c> at the store root, replaced atomically.
/// </summary>
public sealed class FileRulePackStore : IRulePackStore
{
    private const string StagingDirName = "staging";
    private const string PackagesDirName = "packages";
    private const string ActiveFileName = "active.json";

    private static readonly JsonSerializerOptions ActiveJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
    };

    private readonly string _basePath;

    public FileRulePackStore()
        : this(GetDefaultBasePath())
    {
    }

    public FileRulePackStore(string basePath)
    {
        ArgumentNullException.ThrowIfNull(basePath);
        _basePath = Path.GetFullPath(basePath);
    }

    private static string GetDefaultBasePath()
    {
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.Create);
        return Path.Combine(localAppData, "SecurityReviewTool", "rules");
    }

    // ------------------------------------------------------------------ IRulePackStore

    /// <inheritdoc />
    public async Task<StoreResult> StoreAsync(
        byte[] zipBytes,
        RulePackManifest manifest,
        string sha256,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(zipBytes);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);

        // 1. Clean up any interrupted staging from a previous run.
        TryRecoverStaging();

        // 2. Create staging directory.
        string stagingDir = Path.Combine(_basePath, StagingDirName,
            Guid.NewGuid().ToString("N"));
        string tempFile = Path.Combine(stagingDir, "package.zip");
        Directory.CreateDirectory(stagingDir);

        try
        {
            // 3. Validate parent directories up to the base path are normal
            //    directories (not reparse points / junctions).
            EnsureNoReparsePointsAbove(stagingDir);

            // 4. Write ZIP bytes to a temp file in staging.
            await using (var fs = new FileStream(tempFile, FileMode.CreateNew,
                FileAccess.Write, FileShare.None,
                bufferSize: 81_920,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await fs.WriteAsync(zipBytes, cancellationToken).ConfigureAwait(false);
                // 5. Flush to stable storage.
                fs.Flush(flushToDisk: true);
            }

            // 6. Move to final immutable path.
            string packagesRoot = Path.Combine(_basePath, PackagesDirName);
            string relativeFinal = Path.Combine(manifest.RulePackId, manifest.Version,
                $"{sha256}.zip");
            string finalPath = Path.Combine(packagesRoot, relativeFinal);
            Directory.CreateDirectory(Path.GetDirectoryName(finalPath)!);

            File.Move(tempFile, finalPath, overwrite: false);

            // 7. Mark final file as read-only.
            File.SetAttributes(finalPath, File.GetAttributes(finalPath) | FileAttributes.ReadOnly);

            // 8. Delete staging directory.
            Directory.Delete(stagingDir, recursive: true);

            return new StoreResult(true, finalPath);
        }
        catch
        {
            // Best-effort cleanup of the staging directory on failure.
            try
            {
                if (Directory.Exists(stagingDir))
                {
                    Directory.Delete(stagingDir, recursive: true);
                }
            }
            catch
            {
                // Swallow cleanup failures.
            }

            throw;
        }
    }

    /// <inheritdoc />
    public async Task<ActivePointer?> GetActiveAsync(CancellationToken cancellationToken)
    {
        string activePath = Path.Combine(_basePath, ActiveFileName);
        if (!File.Exists(activePath))
        {
            return null;
        }

        byte[] jsonBytes = await File.ReadAllBytesAsync(activePath, cancellationToken)
            .ConfigureAwait(false);

        return JsonSerializer.Deserialize<ActivePointer>(jsonBytes, ActiveJsonOptions);
    }

    /// <summary>
    /// Reads an immutable stored package by its content hash and verifies the
    /// bytes again before returning them to the runtime detector pipeline.
    /// </summary>
    public async Task<byte[]> ReadPackageByHashAsync(
        string sha256,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        byte[] expectedHash;
        try
        {
            expectedHash = Convert.FromHexString(sha256);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("The active rule package hash is invalid.");
        }

        if (expectedHash.Length != 32)
        {
            throw new InvalidOperationException("The active rule package hash is invalid.");
        }

        string packagesRoot = Path.Combine(_basePath, PackagesDirName);
        if (!Directory.Exists(packagesRoot))
        {
            throw new FileNotFoundException("The active rule package is missing.");
        }

        string fileName = $"{sha256.ToLowerInvariant()}.zip";
        string? packagePath = Directory
            .EnumerateFiles(packagesRoot, "*.zip", SearchOption.AllDirectories)
            .FirstOrDefault(path => string.Equals(
                Path.GetFileName(path), fileName, StringComparison.OrdinalIgnoreCase));
        if (packagePath is null)
        {
            throw new FileNotFoundException("The active rule package is missing.");
        }

        byte[] bytes = await File.ReadAllBytesAsync(packagePath, cancellationToken)
            .ConfigureAwait(false);
        byte[] actualHash = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
        {
            throw new InvalidDataException("The active rule package failed integrity verification.");
        }

        return bytes;
    }

    /// <inheritdoc />
    public async Task SetActiveAsync(ActivePointer activePointer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(activePointer);

        string activePath = Path.Combine(_basePath, ActiveFileName);
        Directory.CreateDirectory(_basePath);

        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(activePointer, ActiveJsonOptions);

        // Write to a temp file on the same volume, then atomically replace.
        string tempPath = activePath + ".tmp";
        await File.WriteAllBytesAsync(tempPath, jsonBytes, cancellationToken)
            .ConfigureAwait(false);

        File.Move(tempPath, activePath, overwrite: true);
    }

    /// <inheritdoc />
    public bool TryRecoverStaging()
    {
        string stagingRoot = Path.Combine(_basePath, StagingDirName);
        if (!Directory.Exists(stagingRoot))
        {
            return true;
        }

        bool allCleared = true;
        foreach (string sub in Directory.EnumerateDirectories(stagingRoot))
        {
            try
            {
                Directory.Delete(sub, recursive: true);
            }
            catch
            {
                allCleared = false;
            }
        }

        return allCleared;
    }

    // ---------------------------------------------------------------------- Helpers

    /// <summary>
    /// Walks up from <paramref name="path"/> to <see cref="_basePath"/> and asserts
    /// that no parent directory is a reparse point (junction / symlink).
    /// </summary>
    private void EnsureNoReparsePointsAbove(string path)
    {
        string? current = Path.GetFullPath(path);
        string baseFull = Path.GetFullPath(_basePath)
            .TrimEnd(Path.DirectorySeparatorChar);

        while (current is not null
               && current.Length >= baseFull.Length
               && !string.Equals(current, baseFull, StringComparison.OrdinalIgnoreCase))
        {
            if (Directory.Exists(current)
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException(
                    $"Parent directory is a reparse point and cannot be used for staging: {current}");
            }

            current = Path.GetDirectoryName(current);
        }
    }
}
