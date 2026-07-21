using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityReview.ContractTests.Rules;

internal sealed record StrictCategoriesPayload(
    int SchemaVersion,
    List<StrictCategoryDto> Categories);

internal sealed record StrictCategoryDto(
    string CategoryId,
    string Name,
    string Description,
    bool Enabled);

internal sealed record StrictAssetsPayload(
    int SchemaVersion,
    List<StrictAssetDto> Assets);

internal sealed record StrictAssetDto(
    string AssetTypeId,
    string Name,
    string Description,
    Dictionary<string, double>? FocusWeights,
    List<StrictComplianceRuleDto>? ComplianceRules);

internal sealed record StrictComplianceRuleDto(
    string Id,
    string AssetTypeId,
    string Name,
    string Description,
    string EvidenceField,
    string RequiredStatus);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(StrictCategoriesPayload))]
internal sealed partial class CategoriesStrictContext : JsonSerializerContext
{
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(StrictAssetsPayload))]
internal sealed partial class AssetsStrictContext : JsonSerializerContext
{
}
