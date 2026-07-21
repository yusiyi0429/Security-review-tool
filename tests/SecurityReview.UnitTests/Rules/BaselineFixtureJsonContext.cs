using System.Text.Json.Serialization;

namespace SecurityReview.UnitTests.Rules;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(BaselineCategoriesPayload))]
internal sealed partial class CategoriesJsonContext : JsonSerializerContext
{
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(BaselineAssetsPayload))]
internal sealed partial class AssetsJsonContext : JsonSerializerContext
{
}
