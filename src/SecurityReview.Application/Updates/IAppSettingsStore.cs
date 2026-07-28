namespace SecurityReview.Application.Updates;

/// <summary>
/// Persists user-level application settings (currently only the update
/// opt-in) as a small JSON document under the per-user config directory.
/// The implementation lives in Infrastructure and follows the
/// <c>JsonLlmConfigurationStore</c> pattern: schema version, atomic write
/// via a temp file, and fallback to <see cref="AppSettings.Default"/> when
/// the document is missing or corrupt. Settings contain no sensitive values.
/// </summary>
public interface IAppSettingsStore
{
    /// <summary>
    /// Loads the stored settings, or <see cref="AppSettings.Default"/> when
    /// none exist or the document is corrupt.
    /// </summary>
    Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>Persists the supplied settings atomically.</summary>
    Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default);
}

/// <summary>
/// User-level application settings. All flags default to the most private
/// behavior: no outbound contact happens unless the user explicitly opts in.
/// </summary>
public sealed record AppSettings(
    bool AutoCheckUpdatesOnStartup = false)
{
    /// <summary>Default settings: automatic update checks disabled.</summary>
    public static readonly AppSettings Default = new();
}
