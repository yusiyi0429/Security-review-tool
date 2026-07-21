namespace SecurityReview.Parsers.Models;

/// <summary>
/// Classification of a dangerous (potentially executable) model format.
/// </summary>
public enum DangerousModelClass
{
    /// <summary>Not a dangerous format.</summary>
    None,
    /// <summary>Pickle protocol detected (never deserialized).</summary>
    PickleProtocol,
    /// <summary>PyTorch archive (ZIP containing pickle members).</summary>
    PyTorchArchive,
    /// <summary>Unknown model format with suspicious markers.</summary>
    SuspiciousModel,
}

/// <summary>
/// Result of classifying a file as a dangerous model format. Never includes
/// deserialized object content; only metadata strings.
/// </summary>
public sealed record DangerousModelClassification(
    DangerousModelClass Class,
    bool IsDangerous,
    IReadOnlyList<string> DetectedProtocols,
    IReadOnlyList<string> ArchiveMembers,
    IReadOnlyList<string> SafeAdjacentFiles,
    string? Detail)
{
    public static DangerousModelClassification Safe() =>
        new(DangerousModelClass.None, false,
            Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), null);

    public static DangerousModelClassification Pickle(IReadOnlyList<string> protocols) =>
        new(DangerousModelClass.PickleProtocol, true,
            protocols, Array.Empty<string>(),
            Array.Empty<string>(), "pickle object serialization — not deserialized, marked NotCovered");

    public static DangerousModelClassification PytorchArchive(IReadOnlyList<string> members,
        IReadOnlyList<string> pickleProtocols) =>
        new(DangerousModelClass.PyTorchArchive, true,
            pickleProtocols, members,
            Array.Empty<string>(), "PyTorch archive — pickle members not deserialized, marked NotCovered");
}
