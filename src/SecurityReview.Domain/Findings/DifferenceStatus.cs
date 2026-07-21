namespace SecurityReview.Domain.Findings;

/// <summary>
/// Indicates whether a finding group represents a new detection, a changed
/// finding, or an unchanged finding relative to a prior scan baseline.
/// </summary>
public enum DifferenceStatus
{
    New,
    Changed,
    Unchanged
}
