using SecurityReview.RulePack.Policy;

namespace SecurityReview.Application.Rules;

/// <summary>
/// Builds an <see cref="EffectivePolicy"/> by merging the active signed rule pack
/// with optional local additive entries and asset filters.
/// </summary>
public interface IEffectivePolicyProvider
{
    Task<EffectivePolicy> BuildAsync(
        ActivePointer active,
        string? localSupplementJson,
        CancellationToken cancellationToken);
}
