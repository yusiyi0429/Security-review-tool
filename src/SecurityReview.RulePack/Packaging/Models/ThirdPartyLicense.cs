using System.Text.Json.Serialization;

namespace SecurityReview.RulePack.Packaging.Models;

/// <summary>
/// A third-party license entry loaded from the rule pack workbook.
/// </summary>
public sealed record ThirdPartyLicense
{
    [JsonPropertyName("license_id")]
    public string LicenseId { get; init; } = "";

    [JsonPropertyName("source_name")]
    public string SourceName { get; init; } = "";

    [JsonPropertyName("fingerprint")]
    public string Fingerprint { get; init; } = "";

    [JsonPropertyName("license_note")]
    public string LicenseNote { get; init; } = "";

    [JsonPropertyName("evidence_ref")]
    public string EvidenceRef { get; init; } = "";

    [JsonPropertyName("valid_from")]
    public string ValidFrom { get; init; } = "";

    [JsonPropertyName("valid_until")]
    public string ValidUntil { get; init; } = "";
}
