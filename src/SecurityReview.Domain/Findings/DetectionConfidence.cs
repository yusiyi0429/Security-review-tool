using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Findings;

[JsonConverter(typeof(JsonStringEnumConverter<DetectionConfidence>))]
public enum DetectionConfidence
{
    High,
    Medium,
    Low
}
