using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.Application.Reviews;

/// <summary>
/// Command to grant a time-bounded exception for an exact finding binding.
/// </summary>
public sealed record GrantExceptionCommand(
    ScanId ScanId,
    FindingOccurrenceId OccurrenceId,
    string AssetId,
    string AssetVersion,
    string FilePath,
    string CanonicalLocator,
    string FindingValue,
    string RulePackHash,
    string RuleId,
    DateTimeOffset ValidUntilUtc,
    string Reason);
