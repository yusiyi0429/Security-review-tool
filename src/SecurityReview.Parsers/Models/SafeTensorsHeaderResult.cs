namespace SecurityReview.Parsers.Models;

/// <summary>
/// Failure reason for a safetensors file that could not be parsed.
/// </summary>
public enum SafeTensorsFailureReason
{
    None,
    Truncated,
    HeaderTooLarge,
    HeaderTooSmall,
    InvalidJson,
    MissingTensorInfo,
    FileLengthMismatch,
}

/// <summary>
/// A single tensor entry in a safetensors header.
/// </summary>
public sealed record SafeTensorEntry(string Name, string Dtype, IReadOnlyList<long> Shape,
    long DataOffsetStart, long DataOffsetEnd);

/// <summary>
/// Result of parsing a safetensors header. Carries tensor names, dtypes,
/// shapes, data offsets, and optional metadata.
/// </summary>
public sealed record SafeTensorsHeaderResult(
    bool IsValid,
    IReadOnlyList<SafeTensorEntry> Tensors,
    IReadOnlyDictionary<string, string> Metadata,
    SafeTensorsFailureReason FailureReason,
    string? FailureDetail,
    long HeaderLength,
    long TotalFileLength)
{
    public static SafeTensorsHeaderResult Failure(SafeTensorsFailureReason reason, string detail) =>
        new(false, Array.Empty<SafeTensorEntry>(),
            new Dictionary<string, string>(),
            reason, detail, 0, 0);
}
