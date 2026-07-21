using System.Collections.Frozen;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Domain.Rules;

namespace SecurityReview.RulePack.Schema;

public sealed record RulePackDocument
{
    public const int MaxRules = 100_000;
    public const int MaxDetectors = 10_000;
    private const int MaxCategoryNameLength = 256;
    private const int MaxDescriptionLength = 2048;

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = 1;

    [JsonPropertyName("categories")]
    public IReadOnlyList<CategoryDefinition> Categories { get; init; } =
        Array.Empty<CategoryDefinition>();

    [JsonPropertyName("assets")]
    public IReadOnlyList<AssetPolicy> Assets { get; init; } =
        Array.Empty<AssetPolicy>();

    [JsonPropertyName("rules")]
    public IReadOnlyList<RuleDefinition> Rules { get; init; } =
        Array.Empty<RuleDefinition>();

    [JsonPropertyName("detectors")]
    public IReadOnlyList<DetectorDefinition> Detectors { get; init; } =
        Array.Empty<DetectorDefinition>();

    [JsonPropertyName("compliance_rules")]
    public IReadOnlyList<ComplianceRule> ComplianceRules { get; init; } =
        Array.Empty<ComplianceRule>();

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (SchemaVersion != 1)
        {
            errors.Add($"Unsupported schema_version: {SchemaVersion}. Only version 1 is supported.");
        }

        // Validate all sub-types
        foreach (var cat in Categories)
        {
            errors.AddRange(cat.Validate());
        }

        foreach (var asset in Assets)
        {
            errors.AddRange(asset.Validate());
        }

        foreach (var rule in Rules)
        {
            errors.AddRange(rule.Validate());
        }

        foreach (var det in Detectors)
        {
            errors.AddRange(det.Validate());
        }

        foreach (var cr in ComplianceRules)
        {
            errors.AddRange(cr.Validate());
        }

        // Capacity limits
        if (Rules.Count > MaxRules)
        {
            errors.Add($"Too many rules: {Rules.Count}; max is {MaxRules}.");
        }

        if (Detectors.Count > MaxDetectors)
        {
            errors.Add($"Too many detectors: {Detectors.Count}; max is {MaxDetectors}.");
        }

        // String length limits
        foreach (var cat in Categories)
        {
            if (cat.Name.Length > MaxCategoryNameLength)
            {
                errors.Add($"Category '{cat.CategoryId.Value}' name too long: {cat.Name.Length}; max {MaxCategoryNameLength}.");
            }

            if (cat.Description.Length > MaxDescriptionLength)
            {
                errors.Add($"Category '{cat.CategoryId.Value}' description too long: {cat.Description.Length}; max {MaxDescriptionLength}.");
            }
        }

        foreach (var asset in Assets)
        {
            if (asset.Name.Length > MaxCategoryNameLength)
            {
                errors.Add($"Asset '{asset.AssetTypeId.Value}' name too long: {asset.Name.Length}; max {MaxCategoryNameLength}.");
            }

            if (asset.Description.Length > MaxDescriptionLength)
            {
                errors.Add($"Asset '{asset.AssetTypeId.Value}' description too long: {asset.Description.Length}; max {MaxDescriptionLength}.");
            }
        }

        // Duplicate ID checks
        var ruleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in Rules)
        {
            if (!ruleIds.Add(rule.Id.Value))
            {
                errors.Add($"Duplicate RuleId: {rule.Id.Value}.");
            }
        }

        var detectorIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var det in Detectors)
        {
            if (!detectorIds.Add(det.Id.Value))
            {
                errors.Add($"Duplicate DetectorId: {det.Id.Value}.");
            }
        }

        // Category uniqueness
        var catIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var cat in Categories)
        {
            if (!catIds.Add(cat.CategoryId.Value))
            {
                errors.Add($"Duplicate CategoryId: {cat.CategoryId.Value}.");
            }
        }

        // Asset uniqueness
        var assetIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var asset in Assets)
        {
            if (!assetIds.Add(asset.AssetTypeId.Value))
            {
                errors.Add($"Duplicate AssetTypeId: {asset.AssetTypeId.Value}.");
            }
        }

        return errors;
    }

    public static RulePackDocument Load(string json)
    {
        var doc = JsonSerializer.Deserialize(json, RulePackJsonContext.Default.RulePackDocument)
            ?? throw new InvalidOperationException("Failed to deserialize RulePackDocument.");
        var errors = doc.Validate();
        if (errors.Count > 0)
        {
            throw new InvalidOperationException(
                $"RulePackDocument validation failed: {string.Join("; ", errors)}");
        }

        return doc;
    }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, RulePackJsonContext.Default.RulePackDocument);
    }

    public byte[] ToUtf8Bytes()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, RulePackJsonContext.Default.RulePackDocument);
    }
}
