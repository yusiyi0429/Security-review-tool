using System.Collections.Frozen;
using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain.Rules;

public sealed record AssetPolicy
{
    [JsonConverter(typeof(AssetTypeIdJsonConverter))]
    public AssetTypeId AssetTypeId { get; init; }

    public string Name { get; init; } = "";
    public string Description { get; init; } = "";

    public Dictionary<CategoryId, double> FocusWeights { get; init; } =
        new Dictionary<CategoryId, double>();
    public IReadOnlyList<ComplianceRule> ComplianceRules { get; init; } =
        Array.Empty<ComplianceRule>();

    /// <summary>
    /// Returns all baseline categories for this asset. Asset policies
    /// add focus weights and compliance rules but never suppress categories.
    /// </summary>
#pragma warning disable CA1822
    public IReadOnlySet<CategoryId> EffectiveCategoryIds(IReadOnlyCollection<CategoryDefinition> baselineCategories)
#pragma warning restore CA1822
    {
        ArgumentNullException.ThrowIfNull(baselineCategories);
        return baselineCategories
            .Select(c => c.CategoryId)
            .ToFrozenSet();
    }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("AssetPolicy Name must not be empty.");
        }

        foreach (var kv in FocusWeights)
        {
            if (double.IsNaN(kv.Value) || double.IsInfinity(kv.Value) || kv.Value < 0)
            {
                errors.Add($"FocusWeight for {kv.Key.Value} is invalid: {kv.Value}.");
            }
        }

        foreach (var cr in ComplianceRules)
        {
            if (cr.AssetTypeId != AssetTypeId)
            {
                errors.Add($"ComplianceRule '{cr.Id}' AssetTypeId mismatch: {cr.AssetTypeId.Value} != {AssetTypeId.Value}.");
            }

            errors.AddRange(cr.Validate());
        }

        return errors;
    }
}
