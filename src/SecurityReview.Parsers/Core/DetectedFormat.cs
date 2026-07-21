namespace SecurityReview.Parsers.Core;

/// <summary>
/// Result of format sniffing: which format was detected, with what confidence,
/// what signature evidence was observed, and whether the extension contradicted
/// the detected format.
/// </summary>
public sealed record DetectedFormat(
    string FormatId,
    double Confidence,
    IReadOnlyList<string> SignatureEvidence,
    bool FormatExtensionMismatch)
{
    public static DetectedFormat Create(string formatId, double confidence,
        IReadOnlyList<string> evidence, bool mismatch) =>
        new(formatId, confidence, evidence, mismatch);
}
