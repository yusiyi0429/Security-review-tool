using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Updates;

namespace SecurityReview.Infrastructure.Updates;

/// <summary>
/// GitHub Releases backed <see cref="IAppUpdateService"/>. Performs the
/// only outbound network calls of the update feature: version discovery
/// against <c>api.github.com</c> and installer/sidecar download from
/// <c>github.com</c> / <c>*.githubusercontent.com</c>.
///
/// Transport hardening (production constructor): no proxy, no cookies,
/// certificate revocation checking enabled, HTTPS only, 10 second
/// connect timeout. Every request — including every redirect hop — is
/// validated against the per-purpose host allowlist before it is sent.
///
/// Redirects are followed manually (<see cref="HttpClientHandler.AllowAutoRedirect"/>
/// is <c>false</c>): the release asset URL answers 302 to a signed CDN
/// URL, and following manually lets the service validate each hop's
/// target host <em>before</em> connecting to it. With auto-redirect the
/// connection to an arbitrary host would already have happened by the
/// time the final response could be inspected.
///
/// The installer is streamed to <c>IApplicationPaths.Temp</c> while its
/// SHA-256 is computed incrementally; afterwards the published sidecar
/// digest is fetched and compared. Any mismatch, unparseable sidecar,
/// size-cap violation, or other failure deletes the temp file (fail
/// closed) and throws <see cref="UpdateVerificationException"/>.
/// </summary>
public sealed class GitHubAppUpdateService : IAppUpdateService, IDisposable
{
    internal const string LatestReleaseApiUrl =
        "https://api.github.com/repos/yusiyi0429/Security-review-tool/releases/latest";
    internal const string ReleasesPageUrl =
        "https://github.com/yusiyi0429/Security-review-tool/releases";

    internal const long MaxInstallerBytes = 500L * 1024 * 1024;
    private const int MaxSidecarBytes = 4096;
    private const int MaxRedirectHops = 5;
    private const int StreamBufferSize = 81920;
    private const string InstallerAssetSuffix = "-win-x64-setup.exe";
    private const string Sha256AssetSuffix = "-win-x64-setup.exe.sha256";
    private const string GitHubApiHost = "api.github.com";
    private const string GitHubHost = "github.com";
    private const string GitHubContentSuffix = ".githubusercontent.com";

    private readonly IApplicationPaths _paths;
    private readonly string _currentVersion;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly bool _isPortableInstall;
    private readonly long _maxInstallerBytes;

    /// <summary>
    /// Production constructor. Builds the hardened HTTP transport and
    /// detects the current version and install layout from the running
    /// process.
    /// </summary>
    public GitHubAppUpdateService(IApplicationPaths paths)
        : this(paths, ResolveCurrentVersion())
    {
    }

    /// <summary>
    /// Production constructor with an explicit current version (the
    /// <c>major.minor.patch</c> display form). Builds the hardened HTTP
    /// transport.
    /// </summary>
    public GitHubAppUpdateService(IApplicationPaths paths, string currentVersion)
        : this(
            paths,
            currentVersion,
            CreateHttpClient(),
            ownsHttpClient: true,
            isPortableInstall: DetectPortableInstall(),
            maxInstallerBytes: MaxInstallerBytes)
    {
    }

    /// <summary>
    /// Test seam: accepts a pre-built <see cref="HttpClient"/> (e.g. one
    /// wrapping an in-memory <see cref="HttpMessageHandler"/>), the
    /// install-layout flag, and the size cap, so no real network, process
    /// state, or 500 MB fixture is needed.
    /// </summary>
    internal GitHubAppUpdateService(
        IApplicationPaths paths,
        string currentVersion,
        HttpClient httpClient,
        bool ownsHttpClient,
        bool isPortableInstall,
        long maxInstallerBytes)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentVersion);
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxInstallerBytes, 1L);

        _paths = paths;
        _currentVersion = currentVersion;
        _httpClient = httpClient;
        _ownsHttpClient = ownsHttpClient;
        _isPortableInstall = isPortableInstall;
        _maxInstallerBytes = maxInstallerBytes;
    }

    public async Task<AppUpdateCheckResult> CheckForUpdateAsync(CancellationToken cancellationToken)
    {
        var apiUri = new Uri(LatestReleaseApiUrl, UriKind.Absolute);
        ValidateApiUri(apiUri);

        using var request = CreateRequest(apiUri);
        using var response = await _httpClient
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var document = await JsonDocument
            .ParseAsync(stream, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return ParseLatestRelease(document.RootElement);
    }

    public async Task<AppDownloadResult> DownloadInstallerAsync(
        AppUpdateCheckResult check,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(check);
        if (check.InstallerUrl is null || check.Sha256Url is null)
        {
            throw new ArgumentException(
                "The update check result carries no installer asset URLs.", nameof(check));
        }

        Directory.CreateDirectory(_paths.Temp);
        var fileName = string.Concat(
            "update-", check.LatestVersion, "-", Guid.NewGuid().ToString("N"), ".exe");
        var installerPath = Path.Combine(_paths.Temp, fileName);

        try
        {
            var actualHash = await DownloadToFileAsync(
                check.InstallerUrl, installerPath, progress, cancellationToken)
                .ConfigureAwait(false);
            var expectedHash = await DownloadExpectedHashAsync(check.Sha256Url, cancellationToken)
                .ConfigureAwait(false);

            if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new UpdateVerificationException(
                    "The downloaded installer hash does not match the published SHA-256 digest.");
            }

            return new AppDownloadResult(installerPath, actualHash);
        }
        catch
        {
            // Fail closed: the partial or completed artifact is deleted on
            // every failure path, including cancellation, and is never
            // left behind for later execution.
            TryDeleteFile(installerPath);
            throw;
        }
    }

    /// <summary>
    /// Pure install-layout test: returns <c>true</c> (portable) unless the
    /// running executable sits under
    /// <c>{LocalApplicationData}\Programs\SecurityReviewTool</c>.
    /// Anything indeterminable is treated as portable so the caller never
    /// auto-launches an installer for a layout it does not recognize.
    /// </summary>
    internal static bool IsPortableInstall(string? processPath, string localApplicationData)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return true;
        }

        string fullProcessPath;
        try
        {
            fullProcessPath = Path.GetFullPath(processPath);
        }
        catch (Exception ex) when (ex is ArgumentException
            or NotSupportedException
            or PathTooLongException)
        {
            return true;
        }

        var installRoot = Path.GetFullPath(
            Path.Combine(localApplicationData, "Programs", "SecurityReviewTool"));
        var rootWithSeparator = installRoot.EndsWith(Path.DirectorySeparatorChar)
            ? installRoot
            : installRoot + Path.DirectorySeparatorChar;

        return !fullProcessPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Download-host allowlist: exactly <c>github.com</c> or any host under
    /// <c>githubusercontent.com</c> (the release asset URL 302-redirects to
    /// a signed CDN URL there).
    /// </summary>
    internal static bool IsDownloadHostAllowed(string host) =>
        string.Equals(host, GitHubHost, StringComparison.OrdinalIgnoreCase)
        || string.Equals(host, "githubusercontent.com", StringComparison.OrdinalIgnoreCase)
        || host.EndsWith(GitHubContentSuffix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Parses the sidecar format <c>&lt;hex&gt;&lt;whitespace&gt;&lt;filename&gt;</c>;
    /// tolerates one or more spaces/tabs between digest and filename and
    /// surrounding whitespace. Throws <see cref="UpdateVerificationException"/>
    /// when the digest token is not 64 hex characters.
    /// </summary>
    internal static string ParseSidecar(string content)
    {
        ArgumentNullException.ThrowIfNull(content);

        var span = content.Trim().AsSpan();
        var end = 0;
        while (end < span.Length && !char.IsWhiteSpace(span[end]))
        {
            end++;
        }

        var token = span[..end];
        if (token.Length != 64 || !IsHex(token))
        {
            throw new UpdateVerificationException(
                "The published SHA-256 sidecar could not be parsed.");
        }

        return token.ToString();
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            CheckCertificateRevocationList = true,
            // Redirects are followed manually with per-hop host validation;
            // see the class remarks.
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            // Generous overall ceiling so a 500 MB installer on a slow link
            // can finish; connect establishment is capped separately above.
            Timeout = TimeSpan.FromMinutes(15),
        };
    }

    private HttpRequestMessage CreateRequest(Uri uri)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd($"SecurityReviewTool/{_currentVersion}");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return request;
    }

    private AppUpdateCheckResult ParseLatestRelease(JsonElement root)
    {
        var tagName = TryGetString(root, "tag_name");
        var htmlUrl = TryGetString(root, "html_url");
        var releasePage = Uri.TryCreate(htmlUrl, UriKind.Absolute, out var pageUri)
            && string.Equals(pageUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? pageUri
                : new Uri(ReleasesPageUrl, UriKind.Absolute);

        // Prerelease or malformed tags are reported as "no update available"
        // (per the IAppUpdateService contract), never as a crash.
        if (!UpdateVersionComparer.TryParseTag(tagName, out var latestVersion)
            || !UpdateVersionComparer.IsNewer(_currentVersion, tagName))
        {
            return new AppUpdateCheckResult(
                _currentVersion,
                latestVersion?.ToString() ?? _currentVersion,
                UpdateAvailable: false,
                InstallerUrl: null,
                Sha256Url: null,
                releasePage,
                _isPortableInstall);
        }

        Uri? installerUrl = null;
        Uri? sha256Url = null;
        if (root.TryGetProperty("assets", out var assets)
            && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in assets.EnumerateArray())
            {
                var name = TryGetString(asset, "name");
                var downloadUrl = TryGetString(asset, "browser_download_url");
                if (name is null
                    || downloadUrl is null
                    || !Uri.TryCreate(downloadUrl, UriKind.Absolute, out var assetUri))
                {
                    continue;
                }

                if (name.EndsWith(InstallerAssetSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    installerUrl ??= assetUri;
                }
                else if (name.EndsWith(Sha256AssetSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    sha256Url ??= assetUri;
                }
            }
        }

        return new AppUpdateCheckResult(
            _currentVersion,
            latestVersion.ToString(),
            UpdateAvailable: true,
            installerUrl,
            sha256Url,
            releasePage,
            _isPortableInstall);
    }

    private async Task<string> DownloadToFileAsync(
        Uri installerUrl,
        string destinationPath,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        using var response = await SendWithRedirectsAsync(installerUrl, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength > _maxInstallerBytes)
        {
            throw new UpdateVerificationException(
                "The installer exceeds the maximum allowed download size.");
        }

        await using var source = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            StreamBufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[StreamBufferSize];
        long total = 0;
        var lastReported = -1;
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > _maxInstallerBytes)
            {
                throw new UpdateVerificationException(
                    "The installer exceeds the maximum allowed download size.");
            }

            hash.AppendData(buffer, 0, read);
            await destination.WriteAsync(
                buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);

            if (contentLength is > 0 && progress is not null)
            {
                var percent = (int)Math.Min(100L, total * 100L / contentLength.Value);
                if (percent != lastReported)
                {
                    lastReported = percent;
                    progress.Report(percent);
                }
            }
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private async Task<string> DownloadExpectedHashAsync(
        Uri sha256Url, CancellationToken cancellationToken)
    {
        using var response = await SendWithRedirectsAsync(sha256Url, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength > MaxSidecarBytes)
        {
            throw new UpdateVerificationException(
                "The published SHA-256 sidecar is unexpectedly large.");
        }

        var text = await response.Content
            .ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false);
        if (text.Length > MaxSidecarBytes)
        {
            throw new UpdateVerificationException(
                "The published SHA-256 sidecar is unexpectedly large.");
        }

        return ParseSidecar(text);
    }

    private async Task<HttpResponseMessage> SendWithRedirectsAsync(
        Uri uri, CancellationToken cancellationToken)
    {
        var current = uri;
        for (var hop = 0; ; hop++)
        {
            ValidateDownloadUri(current);

            using var request = CreateRequest(current);
            var response = await _httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (!IsRedirectStatus(response.StatusCode))
            {
                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();

            if (location is null)
            {
                throw new UpdateVerificationException(
                    "The download server returned a redirect without a location.");
            }

            if (hop >= MaxRedirectHops)
            {
                throw new UpdateVerificationException(
                    "The download exceeded the maximum redirect count.");
            }

            current = new Uri(current, location);
        }
    }

    private static void ValidateApiUri(Uri uri)
    {
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.Host, GitHubApiHost, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The update API request target is not allowlisted.");
        }
    }

    private static void ValidateDownloadUri(Uri uri)
    {
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Only HTTPS update download URLs are allowed.");
        }

        if (!IsDownloadHostAllowed(uri.Host))
        {
            throw new InvalidOperationException("The update download host is not allowlisted.");
        }
    }

    private static bool IsRedirectStatus(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Redirect
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(propertyName, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }

    private static string ResolveCurrentVersion()
    {
        var informational = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(informational))
        {
            return "0.0.0";
        }

        // Strip source-control build metadata ("1.2.3+abcdef") so the tag
        // comparison sees a plain major.minor.patch version.
        var plusIndex = informational.IndexOf('+', StringComparison.Ordinal);
        return plusIndex >= 0 ? informational[..plusIndex] : informational;
    }

    private static bool DetectPortableInstall()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return IsPortableInstall(Environment.ProcessPath ?? AppContext.BaseDirectory, localAppData);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort only; the original exception still propagates.
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
