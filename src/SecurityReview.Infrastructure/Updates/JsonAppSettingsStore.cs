using System.Text;
using System.Text.Json;
using SecurityReview.Application.Updates;

namespace SecurityReview.Infrastructure.Updates;

/// <summary>
/// JSON-backed implementation of <see cref="IAppSettingsStore"/>. The
/// on-disk document is a minimal schema-versioned envelope written
/// atomically via a temp file and <see cref="File.Move(string, string, bool)"/>.
/// Because settings only gate a convenience feature (update checks) and
/// contain no sensitive values, a missing or corrupt document falls back
/// to <see cref="AppSettings.Default"/> instead of failing.
/// </summary>
public sealed class JsonAppSettingsStore : IAppSettingsStore
{
    /// <summary>Schema version of the on-disk document.</summary>
    public const int SchemaVersion = 1;

    /// <summary>File name of the settings document inside the config directory.</summary>
    public const string FileName = "app-settings.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private readonly string _configDirectory;

    /// <summary>
    /// Constructs the store rooted at the supplied config directory
    /// (typically <c>AppDataPaths.Config</c>).
    /// </summary>
    public JsonAppSettingsStore(string configDirectory)
    {
        ArgumentNullException.ThrowIfNull(configDirectory);
        _configDirectory = Path.GetFullPath(configDirectory);
    }

    /// <summary>Path to the atomic on-disk settings document.</summary>
    public string FilePath => Path.Combine(_configDirectory, FileName);

    public async Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(FilePath))
            return AppSettings.Default;

        AppSettingsDocument? document;
        try
        {
            string json = await File.ReadAllTextAsync(FilePath, cancellationToken)
                .ConfigureAwait(false);
            document = JsonSerializer.Deserialize<AppSettingsDocument>(json, JsonOptions);
        }
        catch (JsonException)
        {
            // Corrupt document — fall back to the most private defaults.
            return AppSettings.Default;
        }
        catch (IOException)
        {
            return AppSettings.Default;
        }
        catch (UnauthorizedAccessException)
        {
            return AppSettings.Default;
        }

        if (document is null || document.SchemaVersion != SchemaVersion)
            return AppSettings.Default;

        return new AppSettings(
            AutoCheckUpdatesOnStartup: document.AutoCheckUpdatesOnStartup);
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        cancellationToken.ThrowIfCancellationRequested();

        var document = new AppSettingsDocument
        {
            SchemaVersion = SchemaVersion,
            AutoCheckUpdatesOnStartup = settings.AutoCheckUpdatesOnStartup,
        };

        await WriteAtomicAsync(document, cancellationToken).ConfigureAwait(false);
    }

    private async Task WriteAtomicAsync(
        AppSettingsDocument document, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_configDirectory);
        string json = JsonSerializer.Serialize(document, JsonOptions);
        string tmp = FilePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            await File.WriteAllBytesAsync(tmp, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
            throw;
        }
    }

    /// <summary>Schema-versioned on-disk envelope for the settings document.</summary>
    private sealed record AppSettingsDocument
    {
        public int SchemaVersion { get; init; }
        public bool AutoCheckUpdatesOnStartup { get; init; }
    }
}
