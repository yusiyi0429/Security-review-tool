using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.Application.Reviews;

/// <summary>
/// Command to record a human review decision on a finding.
/// Supports both group-level and occurrence-level decisions.
/// </summary>
public sealed record RecordReviewCommand(
    ScanId ScanId,
    FindingGroupId? GroupId,
    FindingOccurrenceId? OccurrenceId,
    ReviewStatus Status,
    string ReasonCode,
    string Reason);
