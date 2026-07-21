using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Findings;

[JsonConverter(typeof(JsonStringEnumConverter<FindingKind>))]
public enum FindingKind
{
    SensitiveContent,
    AssetCompliance
}
