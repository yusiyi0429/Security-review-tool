using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain.Rules;

public sealed record ComplianceRule
{
    public string Id { get; init; } = "";

    [JsonConverter(typeof(AssetTypeIdJsonConverter))]
    public AssetTypeId AssetTypeId { get; init; }
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string EvidenceField { get; init; } = "";
    public string RequiredStatus { get; init; } = "";

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Id))
        {
            errors.Add("ComplianceRule Id must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("ComplianceRule Name must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(EvidenceField))
        {
            errors.Add("ComplianceRule EvidenceField must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(RequiredStatus))
        {
            errors.Add("ComplianceRule RequiredStatus must not be empty.");
        }

        return errors;
    }
}
