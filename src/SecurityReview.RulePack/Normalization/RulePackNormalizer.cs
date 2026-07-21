using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePack.Normalization;

public static class RulePackNormalizer
{
    /// <summary>
    /// Produces a canonical copy of <paramref name="document"/> with every
    /// collection deterministically ordered by its natural identifier.
    /// </summary>
    public static RulePackDocument Normalize(RulePackDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        return document with
        {
            Categories = document.Categories
                .OrderBy(c => c.CategoryId.Value, StringComparer.Ordinal)
                .ToList(),

            Assets = document.Assets
                .OrderBy(a => a.AssetTypeId.Value, StringComparer.Ordinal)
                .ToList(),

            Rules = document.Rules
                .OrderBy(r => r.Id.Value, StringComparer.Ordinal)
                .ToList(),

            Detectors = document.Detectors
                .OrderBy(d => d.Id.Value, StringComparer.Ordinal)
                .ToList(),

            ComplianceRules = document.ComplianceRules
                .OrderBy(cr => cr.Id, StringComparer.Ordinal)
                .ToList(),
        };
    }
}
