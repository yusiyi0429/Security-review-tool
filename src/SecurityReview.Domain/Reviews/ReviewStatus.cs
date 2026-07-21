namespace SecurityReview.Domain.Reviews;

/// <summary>
/// Outcome of a human review decision on a finding group or occurrence.
/// Non-Pending states require an encrypted reason (1–2,000 characters).
/// </summary>
public enum ReviewStatus
{
    /// <summary>Not yet reviewed.</summary>
    Pending,

    /// <summary>Human reviewer confirms the finding is a real risk.</summary>
    ConfirmedRisk,

    /// <summary>Human reviewer determines the finding is a false positive.</summary>
    FalsePositive,

    /// <summary>An approved exception grants temporary exemption from this finding.</summary>
    ApprovedException,

    /// <summary>The finding was remediated and is awaiting rescan verification.</summary>
    RemediatedAwaitingRescan
}
