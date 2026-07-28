using System.Security.Cryptography;
using SecurityReview.Infrastructure.Rules;

namespace SecurityReview.UnitTests.Rules;

public sealed class RulePackPreviewProviderTests : IDisposable
{
    private readonly string _tempDir =
        Directory.CreateTempSubdirectory("srt-preview-").FullName;

    [Fact]
    public async Task GetActiveRules_returns_null_when_no_pack_is_active()
    {
        var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
        var provider = new RulePackPreviewProvider(
            new ActiveRulePackRuntimeProvider(store),
            Path.Combine(_tempDir, "missing.zip"));

        Assert.Null(await provider.GetActiveRulesAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Bundled_hash_matches_file_contents_as_lowercase_hex()
    {
        string bundledPath = Path.Combine(_tempDir, "default-rule-pack.zip");
        byte[] bytes = [1, 2, 3, 4, 5];
        await File.WriteAllBytesAsync(bundledPath, bytes);
        string expected = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
        var provider = new RulePackPreviewProvider(
            new ActiveRulePackRuntimeProvider(store), bundledPath);

        string? actual = await provider
            .GetBundledBaselineSha256Async(CancellationToken.None);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task Bundled_hash_is_null_when_file_is_missing()
    {
        var store = new FileRulePackStore(Path.Combine(_tempDir, "rules"));
        var provider = new RulePackPreviewProvider(
            new ActiveRulePackRuntimeProvider(store),
            Path.Combine(_tempDir, "missing.zip"));

        Assert.Null(await provider
            .GetBundledBaselineSha256Async(CancellationToken.None));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch (IOException) { }
    }
}
