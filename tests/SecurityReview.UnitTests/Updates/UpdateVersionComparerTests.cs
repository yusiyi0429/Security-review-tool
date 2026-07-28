using SecurityReview.Application.Updates;

namespace SecurityReview.UnitTests.Updates;

public sealed class UpdateVersionComparerTests
{
    [Theory]
    [InlineData("v1.2.3", 1, 2, 3)]
    [InlineData("1.2.3", 1, 2, 3)]
    [InlineData("V2.0.10", 2, 0, 10)]
    [InlineData("  v0.1.0  ", 0, 1, 0)]
    public void Try_parse_tag_accepts_stable_three_part_tags(string tag, int major, int minor, int patch)
    {
        var parsed = UpdateVersionComparer.TryParseTag(tag, out var version);

        Assert.True(parsed);
        Assert.NotNull(version);
        Assert.Equal(new Version(major, minor, patch), version);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-version")]
    [InlineData("v1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("v1.2.x")]
    [InlineData("v1.-2.3")]
    public void Try_parse_tag_rejects_malformed_tags(string? tag)
    {
        var parsed = UpdateVersionComparer.TryParseTag(tag, out var version);

        Assert.False(parsed);
        Assert.Null(version);
    }

    [Theory]
    [InlineData("v1.4.0-rc.1")]
    [InlineData("1.4.0-beta")]
    [InlineData("v2.0.0-alpha.1+build.5")]
    public void Try_parse_tag_rejects_prerelease_tags(string tag)
    {
        var parsed = UpdateVersionComparer.TryParseTag(tag, out var version);

        Assert.False(parsed);
        Assert.Null(version);
    }

    [Theory]
    [InlineData("1.2.3", "v1.2.4")]
    [InlineData("v1.2.3", "1.3.0")]
    [InlineData("1.2.3", "2.0.0")]
    [InlineData("v0.9.9", "v0.10.0")]
    public void Is_newer_returns_true_when_latest_is_strictly_newer(string current, string latest)
    {
        Assert.True(UpdateVersionComparer.IsNewer(current, latest));
    }

    [Theory]
    [InlineData("1.2.3", "v1.2.3")]
    [InlineData("v1.2.3", "1.2.3")]
    public void Is_newer_returns_false_for_equal_versions(string current, string latest)
    {
        Assert.False(UpdateVersionComparer.IsNewer(current, latest));
    }

    [Theory]
    [InlineData("1.2.3", "v1.2.2")]
    [InlineData("v2.0.0", "1.9.9")]
    [InlineData("0.10.0", "v0.9.9")]
    public void Is_newer_returns_false_when_latest_is_older(string current, string latest)
    {
        Assert.False(UpdateVersionComparer.IsNewer(current, latest));
    }

    [Theory]
    [InlineData("1.2.3", "v1.4.0-rc.1")]
    [InlineData("v1.4.0-rc.1", "v1.2.3")]
    public void Is_newer_returns_false_when_either_tag_is_prerelease(string current, string latest)
    {
        Assert.False(UpdateVersionComparer.IsNewer(current, latest));
    }

    [Theory]
    [InlineData(null, "v1.2.3")]
    [InlineData("1.2.3", null)]
    [InlineData("not-a-version", "v9.9.9")]
    [InlineData("1.2", "1.2.3.4")]
    public void Is_newer_returns_false_when_either_tag_is_invalid(string? current, string? latest)
    {
        Assert.False(UpdateVersionComparer.IsNewer(current, latest));
    }
}
