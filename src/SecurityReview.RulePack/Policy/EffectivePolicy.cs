using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePack.Policy;

/// <summary>
/// The effective (merged) policy computed from the active signed rule pack,
/// optional local additive entries, and asset filters.
/// </summary>
public sealed record EffectivePolicy
{
    /// <summary>
    /// The final merged rule pack document (always includes all 8 baseline categories).
    /// </summary>
    public RulePackDocument Rules { get; init; } = new();

    /// <summary>
    /// SHA-256 of the canonical JSON representation of this effective policy.
    /// </summary>
    public string PolicySha256 { get; init; } = "";

    /// <summary>
    /// SHA-256 of the active package ZIP.
    /// </summary>
    public string PackageSha256 { get; init; } = "";

    /// <summary>
    /// SHA-256 of the local supplement file, or <c>null</c> if none.
    /// </summary>
    public string? LocalSupplementHash { get; init; }

    /// <summary>
    /// Asset type IDs included in this effective policy.
    /// </summary>
    public IReadOnlySet<string> ActiveAssetIds { get; init; } =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// Detector versions present in this effective policy.
    /// </summary>
    public IReadOnlyDictionary<string, string> ActiveDetectorVersions { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Warnings produced during merge (e.g., non-latest package, local additions present).
    /// </summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
