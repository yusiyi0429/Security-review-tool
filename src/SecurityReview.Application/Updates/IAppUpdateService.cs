namespace SecurityReview.Application.Updates;

/// <summary>
/// Port for checking GitHub Releases for a newer application version and
/// downloading the verified installer. The implementation lives in
/// Infrastructure and performs the only outbound network calls of the
/// application; it is only ever invoked after explicit user action or when
/// the user opted in via <see cref="AppSettings.AutoCheckUpdatesOnStartup"/>.
/// Implementations must fail closed: any download whose SHA-256 does not
/// match the published sidecar digest is deleted and reported as an error.
/// </summary>
public interface IAppUpdateService
{
    /// <summary>
    /// Queries the latest stable release and compares it against the running
    /// version. Prerelease tags are ignored (reported as no update available).
    /// Throws on network or protocol failure; it never returns a partial result.
    /// </summary>
    Task<AppUpdateCheckResult> CheckForUpdateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Downloads the installer referenced by <paramref name="check"/> to a
    /// per-user temp location, verifying its SHA-256 against the published
    /// sidecar digest before returning. <paramref name="progress"/> receives
    /// download completion percentages (0-100) and may be <c>null</c>.
    /// A verification mismatch deletes the partial file and throws.
    /// </summary>
    Task<AppDownloadResult> DownloadInstallerAsync(
        AppUpdateCheckResult check,
        IProgress<int>? progress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Result of an update check. <see cref="CurrentVersion"/> and
/// <see cref="LatestVersion"/> are display strings in <c>major.minor.patch</c>
/// form (no <c>v</c> prefix); comparison semantics live in
/// <see cref="UpdateVersionComparer"/>. <see cref="InstallerUrl"/> and
/// <see cref="Sha256Url"/> are only populated when
/// <see cref="UpdateAvailable"/> is <c>true</c>.
/// </summary>
public sealed record AppUpdateCheckResult(
    string CurrentVersion,
    string LatestVersion,
    bool UpdateAvailable,
    Uri? InstallerUrl,
    Uri? Sha256Url,
    Uri ReleasePageUrl,
    bool IsPortableInstall);

/// <summary>
/// Result of a completed, hash-verified installer download.
/// <see cref="InstallerPath"/> is an absolute path inside the per-user temp
/// directory; <see cref="VerifiedSha256"/> is the lowercase hex digest that
/// matched the published sidecar.
/// </summary>
public sealed record AppDownloadResult(
    string InstallerPath,
    string VerifiedSha256);
