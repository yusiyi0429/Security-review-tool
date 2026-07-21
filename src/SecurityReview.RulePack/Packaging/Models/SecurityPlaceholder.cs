using System.Text.Json.Serialization;

namespace SecurityReview.RulePack.Packaging.Models;

/// <summary>
/// A security placeholder entry loaded from the rule pack workbook.
/// </summary>
public sealed record SecurityPlaceholder
{
    [JsonPropertyName("placeholder_id")]
    public string PlaceholderId { get; init; } = "";

    [JsonPropertyName("match_type")]
    public string MatchType { get; init; } = "";

    [JsonPropertyName("value")]
    public string Value { get; init; } = "";

    [JsonPropertyName("allowed_context")]
    public string AllowedContext { get; init; } = "";

    [JsonPropertyName("category_id")]
    public string CategoryId { get; init; } = "";

    [JsonPropertyName("valid_from")]
    public string ValidFrom { get; init; } = "";

    [JsonPropertyName("valid_until")]
    public string ValidUntil { get; init; } = "";
}
