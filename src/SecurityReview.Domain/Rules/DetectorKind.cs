using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Rules;

[JsonConverter(typeof(JsonStringEnumConverter<DetectorKind>))]
public enum DetectorKind
{
    KnownFormat,
    Checksum,
    StructuredField,
    NetworkAddress,
    Dictionary,
    EntropyWithContext,
    LicenseFingerprint,
    ContentFingerprint,
    SemanticCandidate
}
