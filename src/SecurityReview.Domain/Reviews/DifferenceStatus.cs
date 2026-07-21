namespace SecurityReview.Domain.Reviews;

/// <summary>
/// Classifies how a finding in the current scan relates to findings in
/// previous scans of the same asset lineage.
/// </summary>
public enum DifferenceStatus
{
    /// <summary>No prior scan exists for this asset lineage, or the finding
    /// has no match in any prior scan.</summary>
    New,

    /// <summary>The finding matched a finding in the previous scan with the
    /// same asset lineage, path, locator, rule, and value fingerprint.</summary>
    Persistent,

    /// <summary>A previous-scan finding was absent this run AND the
    /// corresponding source location was fully covered this run.</summary>
    Resolved,

    /// <summary>A previous-scan finding was absent this run but the
    /// corresponding source location was NOT covered this run, so
    /// resolution cannot be confirmed.</summary>
    UnreviewableThisRun,

    /// <summary>A rule package change introduced a newly-enabled rule that
    /// matches the same location and value as a previous finding; the old
    /// rule is absent but the finding is attributable to the rule change
    /// rather than being genuinely resolved.</summary>
    ReappearedAfterRuleChange
}
