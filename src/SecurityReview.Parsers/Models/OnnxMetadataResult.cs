namespace SecurityReview.Parsers.Models;

/// <summary>
/// Failure reason for an ONNX model that could not be parsed.
/// </summary>
public enum OnnxFailureReason
{
    None,
    Truncated,
    InvalidVarint,
    OversizedMessage,
}

/// <summary>
/// Result of extracting ONNX model metadata via protobuf wire walking.
/// </summary>
public sealed record OnnxMetadataResult(
    bool IsValid,
    long IrVersion,
    string? ProducerName,
    string? ProducerVersion,
    string? Domain,
    string? DocString,
    IReadOnlyList<string> GraphNames,
    IReadOnlyList<string> NodeNames,
    IReadOnlyList<string> InputNames,
    IReadOnlyList<string> OutputNames,
    IReadOnlyDictionary<string, string> MetadataProps,
    IReadOnlyList<(string Domain, long Version)> OpsetImports,
    OnnxFailureReason FailureReason,
    string? FailureDetail,
    long BytesConsumed)
{
    public static OnnxMetadataResult Failure(OnnxFailureReason reason, string detail) =>
        new(false, 0, null, null, null, null,
            Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), Array.Empty<string>(),
            new Dictionary<string, string>(),
            Array.Empty<(string, long)>(),
            reason, detail, 0);
}
