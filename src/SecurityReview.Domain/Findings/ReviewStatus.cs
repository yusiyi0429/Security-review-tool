namespace SecurityReview.Domain.Findings;

/// <summary>
/// Lifecycle status of an LLM-based semantic review for a finding candidate.
/// </summary>
public enum ReviewStatus
{
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped
}
