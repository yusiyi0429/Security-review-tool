namespace SecurityReview.Parsers.Models;

/// <summary>
/// Failure reason for a GGUF file that could not be parsed.
/// </summary>
public enum GgufFailureReason
{
    None,
    InvalidMagic,
    UnsupportedVersion,
    Truncated,
    ExcessiveTensorCount,
    ExcessiveKvCount,
    OversizedString,
    InvalidString,
}

/// <summary>
/// A single key-value metadata entry from a GGUF header.
/// </summary>
public sealed record GgufMetadataEntry(
    string Key, string ValueType, string? StringValue, long? IntValue, double? FloatValue);

/// <summary>
/// A single tensor info entry from a GGUF header.
/// </summary>
public sealed record GgufTensorInfo(
    string Name, int NDims, IReadOnlyList<long> Shape, string Dtype, long Offset);

/// <summary>
/// Result of parsing a GGUF metadata header.
/// </summary>
public sealed record GgufMetadataResult(
    bool IsValid,
    uint Version,
    IReadOnlyList<GgufMetadataEntry> Entries,
    IReadOnlyList<GgufTensorInfo> Tensors,
    GgufFailureReason FailureReason,
    string? FailureDetail)
{
    public static GgufMetadataResult Failure(GgufFailureReason reason, string detail) =>
        new(false, 0,
            Array.Empty<GgufMetadataEntry>(), Array.Empty<GgufTensorInfo>(),
            reason, detail);
}
