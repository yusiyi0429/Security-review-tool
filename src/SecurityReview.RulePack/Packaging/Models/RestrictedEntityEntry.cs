using System.Text.Json.Serialization;

namespace SecurityReview.RulePack.Packaging.Models;

/// <summary>
/// A restricted entity entry loaded from the rule pack workbook.
/// </summary>
public sealed record RestrictedEntityEntry
{
    [JsonPropertyName("dictionary_id")]
    public string DictionaryId { get; init; } = "";

    [JsonPropertyName("entity_id")]
    public string EntityId { get; init; } = "";

    [JsonPropertyName("standard_name")]
    public string StandardName { get; init; } = "";

    [JsonPropertyName("variant")]
    public string Variant { get; init; } = "";

    [JsonPropertyName("category_id")]
    public string CategoryId { get; init; } = "";

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "";

    [JsonPropertyName("asset_scope")]
    public string AssetScope { get; init; } = "";

    [JsonPropertyName("valid_from")]
    public string ValidFrom { get; init; } = "";

    [JsonPropertyName("valid_until")]
    public string ValidUntil { get; init; } = "";
}
