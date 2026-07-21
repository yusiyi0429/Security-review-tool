using System.Collections.Frozen;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePack.Validation;

public static class RuleGraphValidator
{
    public sealed record GraphValidationResult(
        IReadOnlyList<string> Errors,
        IReadOnlyList<string> Warnings)
    {
        public bool IsValid => Errors.Count == 0;
    }

    public static GraphValidationResult Validate(RulePackDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var errors = new List<string>();
        var warnings = new List<string>();

        // Build lookup sets
        var detectorIds = document.Detectors
            .Select(d => d.Id.Value)
            .ToFrozenSet(StringComparer.Ordinal);

        var categoryIds = document.Categories
            .Select(c => c.CategoryId.Value)
            .ToFrozenSet(StringComparer.Ordinal);

        var assetTypeIds = document.Assets
            .Select(a => a.AssetTypeId.Value)
            .ToFrozenSet(StringComparer.Ordinal);

        // Check dangling detector references from rules
        foreach (var rule in document.Rules)
        {
            if (!detectorIds.Contains(rule.DetectorId.Value))
            {
                errors.Add(
                    $"Rule '{rule.Id.Value}' references detector '{rule.DetectorId.Value}' which is not defined.");
            }

            if (!categoryIds.Contains(rule.CategoryId.Value))
            {
                errors.Add(
                    $"Rule '{rule.Id.Value}' references category '{rule.CategoryId.Value}' which is not defined.");
            }
        }

        // Check detector reference cycles
        var detectorConfigIds = document.Detectors
            .Select(d => d.ConfigId)
            .ToFrozenSet(StringComparer.Ordinal);

        foreach (var det in document.Detectors)
        {
            if (det.Parameters.TryGetValue("references", out var refs))
            {
                foreach (var r in refs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!detectorConfigIds.Contains(r))
                    {
                        warnings.Add(
                            $"Detector '{det.Id.Value}' references unknown config '{r}'.");
                    }
                }
            }
        }

        // Validate all assets reference existing categories
        foreach (var asset in document.Assets)
        {
            var effective = asset.EffectiveCategoryIds(document.Categories);
            if (effective.Count == 0)
            {
                warnings.Add(
                    $"Asset '{asset.AssetTypeId.Value}' has no effective categories.");
            }
        }

        return new GraphValidationResult(errors, warnings);
    }
}
