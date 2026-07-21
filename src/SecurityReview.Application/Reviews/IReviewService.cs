using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.Application.Reviews;

/// <summary>
/// Service for recording review decisions and managing exception grants.
/// </summary>
public interface IReviewService
{
    /// <summary>
    /// Record a review decision on a finding occurrence or group.
    /// Appends a new decision; never mutates prior history.
    /// </summary>
    Task<ReviewDecision> RecordReviewAsync(
        RecordReviewCommand command, CancellationToken ct = default);

    /// <summary>
    /// Grant a time-bounded exception for an exact finding binding.
    /// Creates both an ApprovedException decision and an ExceptionGrant
    /// in the same transaction.
    /// </summary>
    Task<ExceptionGrant> GrantExceptionAsync(
        GrantExceptionCommand command, CancellationToken ct = default);

    /// <summary>
    /// Compute the effective review status for an occurrence by looking at
    /// the latest decision and any active exception grants.
    /// </summary>
    Task<EffectiveReviewResult> GetEffectiveStatusAsync(
        FindingOccurrenceId occurrenceId,
        string assetBindingHmac,
        string occurrenceBindingHmac,
        CancellationToken ct = default);
}

/// <summary>
/// Result of computing the effective review status for an occurrence.
/// </summary>
public sealed record EffectiveReviewResult(
    ReviewStatus Status,
    string ReasonCode,
    DateTimeOffset? DecidedAtUtc);
