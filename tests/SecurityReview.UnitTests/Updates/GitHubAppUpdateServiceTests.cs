using System.Net;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Updates;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Updates;

namespace SecurityReview.UnitTests.Updates;

public sealed class GitHubAppUpdateServiceTests : IDisposable
{
    private const string InstallerUrl =
        "https://github.com/yusiyi0429/Security-review-tool/releases/download/v1.4.0/SecurityReviewTool-1.4.0-win-x64-setup.exe";
    private const string Sha256Url =
        "https://github.com/yusiyi0429/Security-review-tool/releases/download/v1.4.0/SecurityReviewTool-1.4.0-win-x64-setup.exe.sha256";
    private const string ReleasePageUrl =
        "https://github.com/yusiyi0429/Security-review-tool/releases/tag/v1.4.0";

    private static readonly byte[] InstallerPayload = Encoding.UTF8.GetBytes("fake-installer-bytes");

    private readonly string _tempRoot;
    private readonly AppDataPaths _paths;

    public GitHubAppUpdateServiceTests()
    {
        _tempRoot = Path.Combine(
            Path.GetTempPath(), "srt-update-" + Guid.NewGuid().ToString("N"));
        _paths = AppDataPaths.CreateForTest(_tempRoot);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
            Directory.Delete(_tempRoot, recursive: true);
    }

    [Fact]
    public async Task Check_parses_latest_response_and_selects_setup_assets()
    {
        using var service = CreateService(_ => JsonResponse(LatestReleaseJson));

        AppUpdateCheckResult result = await service.CheckForUpdateAsync(CancellationToken.None);

        Assert.True(result.UpdateAvailable);
        Assert.Equal("1.2.3", result.CurrentVersion);
        Assert.Equal("1.4.0", result.LatestVersion);
        Assert.Equal(new Uri(InstallerUrl), result.InstallerUrl);
        Assert.Equal(new Uri(Sha256Url), result.Sha256Url);
        Assert.Equal(new Uri(ReleasePageUrl), result.ReleasePageUrl);
        Assert.True(result.IsPortableInstall);
    }

    [Fact]
    public async Task Check_reports_no_update_when_latest_is_not_newer()
    {
        var json = LatestReleaseJson.Replace("\"v1.4.0\"", "\"v1.2.3\"", StringComparison.Ordinal);
        using var service = CreateService(_ => JsonResponse(json));

        AppUpdateCheckResult result = await service.CheckForUpdateAsync(CancellationToken.None);

        Assert.False(result.UpdateAvailable);
        Assert.Null(result.InstallerUrl);
        Assert.Null(result.Sha256Url);
    }

    [Fact]
    public async Task Check_reports_no_update_for_prerelease_tag()
    {
        var json = LatestReleaseJson.Replace("\"v1.4.0\"", "\"v1.4.0-rc.1\"", StringComparison.Ordinal);
        using var service = CreateService(_ => JsonResponse(json));

        AppUpdateCheckResult result = await service.CheckForUpdateAsync(CancellationToken.None);

        Assert.False(result.UpdateAvailable);
    }

    [Fact]
    public async Task Check_tolerates_missing_assets_and_html_url()
    {
        const string json = """{ "tag_name": "v1.4.0" }""";
        using var service = CreateService(_ => JsonResponse(json));

        AppUpdateCheckResult result = await service.CheckForUpdateAsync(CancellationToken.None);

        Assert.True(result.UpdateAvailable);
        Assert.Null(result.InstallerUrl);
        Assert.Null(result.Sha256Url);
        Assert.Equal(new Uri(GitHubAppUpdateService.ReleasesPageUrl), result.ReleasePageUrl);
    }

    [Fact]
    public async Task Check_sends_user_agent_and_accept_headers()
    {
        var handler = new FakeHttpMessageHandler(_ => JsonResponse(LatestReleaseJson));
        using var service = CreateService(handler);

        await service.CheckForUpdateAsync(CancellationToken.None);

        Assert.Single(handler.Requests);
        Assert.Equal("SecurityReviewTool/1.2.3", handler.Requests[0].UserAgent);
        Assert.Contains("application/vnd.github+json", handler.Requests[0].Accept);
    }

    [Fact]
    public async Task Download_rejects_non_allowlisted_host_before_sending()
    {
        var handler = new FakeHttpMessageHandler(_ => TextResponse("unused"));
        using var service = CreateService(handler);
        var check = NoAssetCheck() with
        {
            InstallerUrl = new Uri("https://evil.example.com/setup.exe"),
            Sha256Url = new Uri("https://evil.example.com/setup.exe.sha256"),
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.DownloadInstallerAsync(check, null, CancellationToken.None));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Download_rejects_http_scheme_before_sending()
    {
        var handler = new FakeHttpMessageHandler(_ => TextResponse("unused"));
        using var service = CreateService(handler);
        var check = NoAssetCheck() with
        {
            InstallerUrl = new Uri("http://github.com/setup.exe"),
            Sha256Url = new Uri("http://github.com/setup.exe.sha256"),
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.DownloadInstallerAsync(check, null, CancellationToken.None));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Download_streams_file_verifies_hash_and_reports_progress()
    {
        var hexUpper = Convert.ToHexString(SHA256.HashData(InstallerPayload));
        using var service = CreateService(DownloadRouter($"{hexUpper}  SecurityReviewTool-1.4.0-win-x64-setup.exe"));
        var progress = new CapturingProgress();

        AppDownloadResult result = await service.DownloadInstallerAsync(
            AvailableCheck(), progress, CancellationToken.None);

        Assert.True(File.Exists(result.InstallerPath));
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(InstallerPayload)), result.VerifiedSha256);
        Assert.Equal(InstallerPayload, await File.ReadAllBytesAsync(result.InstallerPath));
        Assert.StartsWith("update-1.4.0-", Path.GetFileName(result.InstallerPath));
        Assert.NotEmpty(progress.Values);
        Assert.Equal(100, progress.Values[^1]);
    }

    [Theory]
    [InlineData("  ")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData(" \t  ")]
    public async Task Download_accepts_sidecar_whitespace_variants(string separator)
    {
        var hex = Convert.ToHexString(SHA256.HashData(InstallerPayload));
        var sidecar = hex + separator + "SecurityReviewTool-1.4.0-win-x64-setup.exe\r\n";
        using var service = CreateService(DownloadRouter(sidecar));

        AppDownloadResult result = await service.DownloadInstallerAsync(
            AvailableCheck(), null, CancellationToken.None);

        Assert.True(File.Exists(result.InstallerPath));
    }

    [Fact]
    public async Task Download_follows_redirect_to_allowlisted_cdn_host()
    {
        var hex = Convert.ToHexString(SHA256.HashData(InstallerPayload));
        var cdnUri = new Uri("https://objects.githubusercontent.com/release-asset-signed");
        var handler = new FakeHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url == InstallerUrl)
            {
                return new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = cdnUri },
                };
            }

            if (url == cdnUri.AbsoluteUri)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(InstallerPayload),
                };
            }

            return TextResponse(hex + "  setup.exe");
        });
        using var service = CreateService(handler);

        AppDownloadResult result = await service.DownloadInstallerAsync(
            AvailableCheck(), null, CancellationToken.None);

        Assert.True(File.Exists(result.InstallerPath));
        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(cdnUri.AbsoluteUri, handler.Requests[1].Url);
    }

    [Fact]
    public async Task Download_rejects_redirect_to_non_allowlisted_host()
    {
        var handler = new FakeHttpMessageHandler(request =>
        {
            if (request.RequestUri!.AbsoluteUri == InstallerUrl)
            {
                return new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = new Uri("https://evil.example.com/payload.exe") },
                };
            }

            return TextResponse("unused");
        });
        using var service = CreateService(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, CancellationToken.None));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Download_hash_mismatch_deletes_file_and_throws()
    {
        var wrongHash = new string('0', 64);
        using var service = CreateService(DownloadRouter(wrongHash + "  setup.exe"));

        await Assert.ThrowsAsync<UpdateVerificationException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, CancellationToken.None));

        AssertNoTempFiles();
    }

    [Fact]
    public async Task Download_unparseable_sidecar_deletes_file_and_throws()
    {
        using var service = CreateService(DownloadRouter("not-a-hex-digest"));

        await Assert.ThrowsAsync<UpdateVerificationException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, CancellationToken.None));

        AssertNoTempFiles();
    }

    [Fact]
    public async Task Download_rejects_installer_above_size_cap_from_header()
    {
        var handler = new FakeHttpMessageHandler(request =>
        {
            if (request.RequestUri!.AbsoluteUri == InstallerUrl)
            {
                var content = new ByteArrayContent(InstallerPayload);
                content.Headers.ContentLength = GitHubAppUpdateService.MaxInstallerBytes + 1;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
            }

            return TextResponse("unused");
        });
        using var service = CreateService(handler);

        await Assert.ThrowsAsync<UpdateVerificationException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, CancellationToken.None));

        AssertNoTempFiles();
    }

    [Fact]
    public async Task Download_rejects_installer_above_size_cap_while_streaming()
    {
        const long cap = 100;
        var handler = new FakeHttpMessageHandler(request =>
        {
            if (request.RequestUri!.AbsoluteUri == InstallerUrl)
            {
                // No Content-Length header; the cap must be enforced mid-stream.
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StreamContent(new EndlessZeroStream(cap + 1)),
                };
            }

            return TextResponse("unused");
        });
        using var service = CreateService(handler, maxInstallerBytes: cap);

        await Assert.ThrowsAsync<UpdateVerificationException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, CancellationToken.None));

        AssertNoTempFiles();
    }

    [Fact]
    public async Task Download_cancellation_propagates_and_leaves_no_file()
    {
        using var service = CreateService(DownloadRouter("unused"));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.DownloadInstallerAsync(AvailableCheck(), null, cts.Token));

        AssertNoTempFiles();
    }

    [Fact]
    public async Task Download_rejects_check_result_without_asset_urls()
    {
        using var service = CreateService(DownloadRouter("unused"));

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.DownloadInstallerAsync(NoAssetCheck(), null, CancellationToken.None));
    }

    [Theory]
    [InlineData(@"C:\Users\me\AppData\Local\Programs\SecurityReviewTool\SecurityReviewTool.exe", false)]
    [InlineData(@"C:\USERS\ME\APPDATA\LOCAL\PROGRAMS\SECURITYREVIEWTOOL\SecurityReviewTool.exe", false)]
    [InlineData(@"C:\Tools\SecurityReviewTool\SecurityReviewTool.exe", true)]
    [InlineData(@"C:\Users\me\AppData\Local\Programs\SecurityReviewToolPortable\SecurityReviewTool.exe", true)]
    [InlineData(null, true)]
    [InlineData("", true)]
    public void Is_portable_install_detects_per_user_install_layout(string? processPath, bool expectedPortable)
    {
        var localAppData = @"C:\Users\me\AppData\Local";

        Assert.Equal(
            expectedPortable,
            GitHubAppUpdateService.IsPortableInstall(processPath, localAppData));
    }

    private GitHubAppUpdateService CreateService(
        Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        CreateService(new FakeHttpMessageHandler(responder));

    private GitHubAppUpdateService CreateService(
        FakeHttpMessageHandler handler,
        long maxInstallerBytes = GitHubAppUpdateService.MaxInstallerBytes)
    {
        var client = new HttpClient(handler, disposeHandler: true);
        return new GitHubAppUpdateService(
            _paths,
            "1.2.3",
            client,
            ownsHttpClient: true,
            isPortableInstall: true,
            maxInstallerBytes: maxInstallerBytes);
    }

    private void AssertNoTempFiles()
    {
        Assert.False(
            Directory.Exists(_paths.Temp) && Directory.EnumerateFiles(_paths.Temp).Any());
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> DownloadRouter(string sidecarText) =>
        request => request.RequestUri!.AbsoluteUri == InstallerUrl
            ? new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(InstallerPayload),
            }
            : TextResponse(sidecarText);

    private static AppUpdateCheckResult AvailableCheck() =>
        new(
            "1.2.3",
            "1.4.0",
            UpdateAvailable: true,
            new Uri(InstallerUrl),
            new Uri(Sha256Url),
            new Uri(ReleasePageUrl),
            IsPortableInstall: true);

    private static AppUpdateCheckResult NoAssetCheck() =>
        new(
            "1.2.3",
            "1.4.0",
            UpdateAvailable: true,
            InstallerUrl: null,
            Sha256Url: null,
            new Uri(ReleasePageUrl),
            IsPortableInstall: true);

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/vnd.github+json"),
        };

    private static HttpResponseMessage TextResponse(string text) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(text, Encoding.UTF8),
        };

    private const string LatestReleaseJson = """
        {
          "tag_name": "v1.4.0",
          "html_url": "https://github.com/yusiyi0429/Security-review-tool/releases/tag/v1.4.0",
          "assets": [
            {
              "name": "SecurityReviewTool-1.4.0-win-x64-portable.zip",
              "browser_download_url": "https://github.com/yusiyi0429/Security-review-tool/releases/download/v1.4.0/SecurityReviewTool-1.4.0-win-x64-portable.zip"
            },
            {
              "name": "SecurityReviewTool-1.4.0-win-x64-setup.exe",
              "browser_download_url": "https://github.com/yusiyi0429/Security-review-tool/releases/download/v1.4.0/SecurityReviewTool-1.4.0-win-x64-setup.exe"
            },
            {
              "name": "SecurityReviewTool-1.4.0-win-x64-setup.exe.sha256",
              "browser_download_url": "https://github.com/yusiyi0429/Security-review-tool/releases/download/v1.4.0/SecurityReviewTool-1.4.0-win-x64-setup.exe.sha256"
            }
          ]
        }
        """;

    private sealed record CapturedRequest(string Url, string UserAgent, IReadOnlyList<string> Accept);

    private sealed class FakeHttpMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public List<CapturedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new CapturedRequest(
                request.RequestUri!.AbsoluteUri,
                request.Headers.UserAgent.ToString(),
                request.Headers.Accept.Select(a => a.MediaType!).ToArray()));
            return Task.FromResult(responder(request));
        }
    }

    private sealed class CapturingProgress : IProgress<int>
    {
        public List<int> Values { get; } = [];

        public void Report(int value) => Values.Add(value);
    }

    /// <summary>
    /// Stream that yields zero bytes until the given length is exhausted,
    /// without holding the data in memory.
    /// </summary>
    private sealed class EndlessZeroStream(long length) : Stream
    {
        private long _remaining = length;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining == 0)
                return 0;
            var toCopy = (int)Math.Min(count, _remaining);
            Array.Clear(buffer, offset, toCopy);
            _remaining -= toCopy;
            return toCopy;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
