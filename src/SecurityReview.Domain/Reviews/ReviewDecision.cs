namespace SecurityReview.Domain.Reviews;

/// <summary>
/// An append-only review decision on a finding group or occurrence.
/// Decisions are never mutated or deleted; the effective state is the
/// latest decision by (<see cref="DecidedAtUtc"/>, <see cref="Id"/>).
///
/// The reason is encrypted at rest and must never be logged; only the
/// non-sensitive <see cref="ReasonCode"/> is safe for diagnostics.
/// </summary>
public sealed record ReviewDecision(
    DecisionId Id,
    ScanId ScanId,
    FindingGroupId? GroupId,
    FindingOccurrenceId? OccurrenceId,
    ReviewStatus Status,
    string ReasonCode,
    string? EncryptedReason,
    string UserSidHmac,
    DateTimeOffset DecidedAtUtc)
{
    /// <summary>
    /// Create a new review decision with validation.
    /// Non-Pending states require an encrypted reason of 1–2,000 characters.
    /// </summary>
    public static ReviewDecision Create(
        ScanId scanId,
        FindingGroupId? groupId,
        FindingOccurrenceId? occurrenceId,
        ReviewStatus status,
        string reasonCode,
        string? encryptedReason,
        string userSidHmac,
        DateTimeOffset decidedAtUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reasonCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(userSidHmac);

        if (groupId is null && occurrenceId is null)
            throw new ArgumentException("At least one of GroupId or OccurrenceId must be provided.");

        if (status != ReviewStatus.Pending)
        {
            if (string.IsNullOrWhiteSpace(encryptedReason))
                throw new ArgumentException(
                    "A reason is required for all non-Pending review statuses.", nameof(encryptedReason));

            if (encryptedReason.Length is < 1 or > 2_000)
                throw new ArgumentException(
                    "Reason must be 1–2,000 characters.", nameof(encryptedReason));
        }

        return new ReviewDecision(
            new DecisionId(Guid.NewGuid()),
            scanId,
            groupId,
            occurrenceId,
            status,
            reasonCode,
            encryptedReason,
            userSidHmac,
            decidedAtUtc);
    }
}
