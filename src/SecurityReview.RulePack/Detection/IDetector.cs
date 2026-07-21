using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// A detector that scans a content chunk for sensitive data.
/// Each detector handles one <see cref="DetectorKind"/>.
/// </summary>
public interface IDetector
{
    DetectorKind Kind { get; }

    /// <summary>
    /// Scan <paramref name="chunk"/> using the given rule and detector configuration.
    /// Returns the list of detection candidates (may be empty).
    /// Must honor <paramref name="cancellationToken"/> for premature termination.
    /// </summary>
    Task<IReadOnlyList<DetectionCandidate>> DetectAsync(
        ContentChunk chunk,
        RuleDefinition rule,
        DetectorDefinition detector,
        CancellationToken cancellationToken);
}
