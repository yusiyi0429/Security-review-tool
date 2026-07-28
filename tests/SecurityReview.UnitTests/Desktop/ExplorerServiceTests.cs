using SecurityReview.Desktop.Services;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for <see cref="ExplorerService.OpenUrl"/>: only HTTPS URLs may
/// reach the confirmation prompt — plain HTTP and every other scheme are
/// rejected without ever invoking the warning callback or spawning a
/// process.
/// </summary>
public sealed class ExplorerServiceTests
{
    [Fact]
    public void open_url_rejects_plain_http_without_prompting()
    {
        var prompted = false;
        var service = new ExplorerService(_ => { prompted = true; return true; });

        bool opened = service.OpenUrl(new Uri("http://updates.example.com/releases/v1.1.0"));

        Assert.False(opened);
        Assert.False(prompted);
    }

    [Theory]
    [InlineData("file:///C:/temp/setup.exe")]
    [InlineData("ftp://updates.example.com/setup.exe")]
    public void open_url_rejects_non_https_schemes_without_prompting(string url)
    {
        var prompted = false;
        var service = new ExplorerService(_ => { prompted = true; return true; });

        bool opened = service.OpenUrl(new Uri(url));

        Assert.False(opened);
        Assert.False(prompted);
    }

    [Fact]
    public void open_url_returns_false_when_user_declines_warning()
    {
        var prompted = false;
        var service = new ExplorerService(_ => { prompted = true; return false; });

        bool opened = service.OpenUrl(new Uri("https://updates.example.com/releases/v1.1.0"));

        Assert.False(opened);
        Assert.True(prompted);
    }
}
