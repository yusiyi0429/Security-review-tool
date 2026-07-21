using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Findings;

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    Critical,
    High,
    Medium,
    Low,
    Info
}
