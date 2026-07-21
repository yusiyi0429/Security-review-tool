namespace SecurityReview.Domain.Findings;

/// <summary>
/// Outcome of a human review decision on a finding group or occurrence.
/// </summary>
public enum DecisionStatus
{
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Deferred
}
