using System.Security.Cryptography;
using SecurityReview.Application.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.Infrastructure.Rules;

/// <summary>
/// Adapts <see cref="ActiveRulePackRuntimeProvider"/> to the read-only
/// preview port used by the desktop rule-management view.
/// </summary>
public sealed class RulePackPreviewProvider : IRulePackPreviewProvider
{
    private readonly ActiveRulePackRuntimeProvider _runtimeProvider;
    private readonly string _bundledPackPath;

    public RulePackPreviewProvider(ActiveRulePackRuntimeProvider runtimeProvider)
        : this(runtimeProvider, GetDefaultBundledPackPath())
    {
    }

    public RulePackPreviewProvider(
        ActiveRulePackRuntimeProvider runtimeProvider,
        string bundledPackPath)
    {
        _runtimeProvider = runtimeProvider
            ?? throw new ArgumentNullException(nameof(runtimeProvider));
        ArgumentException.ThrowIfNullOrWhiteSpace(bundledPackPath);
        _bundledPackPath = bundledPackPath;
    }

    public async Task<RulePackDocument?> GetActiveRulesAsync(
        CancellationToken cancellationToken)
    {
        ActiveRulePackRuntime? runtime = await _runtimeProvider
            .GetActiveAsync(cancellationToken)
            .ConfigureAwait(false);
        return runtime?.Package.Policy.Rules;
    }

    public async Task<string?> GetBundledBaselineSha256Async(
        CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(_bundledPackPath))
                return null;
            byte[] bytes = await File
                .ReadAllBytesAsync(_bundledPackPath, cancellationToken)
                .ConfigureAwait(false);
            return Convert.ToHexStringLower(SHA256.HashData(bytes));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string GetDefaultBundledPackPath() =>
        Path.Combine(AppContext.BaseDirectory, "Assets", "rules", "default-rule-pack.zip");
}
