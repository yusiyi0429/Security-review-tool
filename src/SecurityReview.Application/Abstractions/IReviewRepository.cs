using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Persistence for review decisions and exception grants.
/// All decisions are append-only; none are ever mutated or deleted.
/// Exception grants are time-bounded and queryable by binding.
/// </summary>
public interface IReviewRepository
{
    /// <summary>
    /// Insert a new review decision. Decisions are append-only.
    /// </summary>
    Task InsertDecisionAsync(ReviewDecision decision, CancellationToken ct = default);

    /// <summary>
    /// Get all decisions for a specific occurrence, ordered by descending
    /// (decided_at_utc, decision_id) so the latest is first.
    /// </summary>
    Task<IReadOnlyList<ReviewDecision>> GetDecisionsByOccurrenceAsync(
        FindingOccurrenceId occurrenceId, CancellationToken ct = default);

    /// <summary>
    /// Get all decisions for a specific group, ordered by descending
    /// (decided_at_utc, decision_id).
    /// </summary>
    Task<IReadOnlyList<ReviewDecision>> GetDecisionsByGroupAsync(
        FindingGroupId groupId, CancellationToken ct = default);

    /// <summary>
    /// Insert a new exception grant.
    /// </summary>
    Task InsertExceptionGrantAsync(ExceptionGrant grant, CancellationToken ct = default);

    /// <summary>
    /// Get active (non-expired) exception grants whose binding hmacs match the
    /// given composite binding key. The composite key is the concatenation of
    /// (asset_binding_hmac, occurrence_binding_hmac).
    /// </summary>
    Task<IReadOnlyList<ExceptionGrant>> GetActiveGrantsByBindingAsync(
        string assetBindingHmac, string occurrenceBindingHmac, CancellationToken ct = default);

    /// <summary>
    /// Get a decision by its ID.
    /// </summary>
    Task<ReviewDecision?> GetDecisionByIdAsync(DecisionId id, CancellationToken ct = default);

    /// <summary>
    /// Get an exception grant by its ID.
    /// </summary>
    Task<ExceptionGrant?> GetGrantByIdAsync(ExceptionGrantId id, CancellationToken ct = default);
}
