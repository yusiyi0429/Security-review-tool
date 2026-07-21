// No additional imports needed
using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Domain.Rules;

public sealed record RuleDefinition
{
    [JsonConverter(typeof(RuleIdJsonConverter))]
    public RuleId Id { get; init; }

    [JsonConverter(typeof(CategoryIdJsonConverter))]
    public CategoryId CategoryId { get; init; }

    public FindingKind FindingKind { get; init; }
    public Severity Severity { get; init; }
    public DetectionConfidence Confidence { get; init; }

    [JsonConverter(typeof(DetectorIdJsonConverter))]
    public DetectorId DetectorId { get; init; }

    public string DetectorConfigId { get; init; } = "";

    public HashSet<AssetTypeId> AppliesToAssets { get; init; } =
        new HashSet<AssetTypeId>();

    public bool RequiresSemanticReview { get; init; }
    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (!IsValidRuleId(Id.Value))
        {
            errors.Add($"Invalid RuleId format: '{Id.Value}'. Must match RULE-[A-Z0-9-]{{3,64}}.");
        }

        if (AppliesToAssets.Count == 0)
        {
            errors.Add("AppliesToAssets must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(DetectorConfigId))
        {
            errors.Add("DetectorConfigId must not be empty.");
        }

        return errors;
    }

    public static bool IsValidRuleId(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        if (!value.StartsWith("RULE-", StringComparison.Ordinal)) return false;

        string suffix = value.AsSpan(5).ToString();
        if (suffix.Length < 3 || suffix.Length > 64) return false;

        foreach (char c in suffix)
        {
            if (!(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-'))
                return false;
        }

        return true;
    }
}
