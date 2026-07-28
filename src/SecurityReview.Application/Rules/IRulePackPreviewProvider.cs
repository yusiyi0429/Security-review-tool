using SecurityReview.RulePack.Schema;

namespace SecurityReview.Application.Rules;

/// <summary>
/// Read-only preview port for the active rule pack document. The desktop
/// rule-management view lists individual rules through this port; it never
/// mutates the store and never bypasses signature validation (the
/// underlying runtime provider revalidates every package on load).
/// </summary>
public interface IRulePackPreviewProvider
{
    /// <summary>
    /// Returns the validated active rule pack document, or <c>null</c>
    /// when no rule pack is active. Throws when the active package is
    /// corrupt or no longer passes validation.
    /// </summary>
    Task<RulePackDocument?> GetActiveRulesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Returns the lowercase SHA-256 hex of the bundled baseline package,
    /// or <c>null</c> when the bundled file is missing or unreadable.
    /// </summary>
    Task<string?> GetBundledBaselineSha256Async(CancellationToken cancellationToken);
}
