namespace SecurityReview.Domain.Findings;

/// <summary>
/// A finding group aggregates all occurrences of the same detected value
/// (matching via keyed value fingerprint) across source locations. Severity
/// is the policy maximum across constituent detections; confidence is
/// independently preserved per provenance.
/// </summary>
public sealed record FindingGroup(
    FindingGroupId Id,
    FindingKind FindingKind,
    Severity Severity,
    ValueFingerprint ValueFingerprint,
    IReadOnlyList<FindingOccurrence> Occurrences)
{
    /// <summary>
    /// Produces a sanitized diagnostic record safe for aggregate reports
    /// and logs — no raw values, only identifiers, category, severity, and count.
    /// </summary>
    public FindingGroupDiagnosticRecord ToDiagnosticRecord() =>
        new(Id, FindingKind, Severity, Occurrences.Count);
}

/// <summary>
/// A sanitized view of a finding group that exposes only classification and
/// count — suitable for reports and dashboards where raw values must not appear.
/// </summary>
public readonly record struct FindingGroupDiagnosticRecord(
    FindingGroupId GroupId,
    FindingKind Category,
    Severity Severity,
    int OccurrenceCount);
