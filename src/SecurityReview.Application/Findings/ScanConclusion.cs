namespace SecurityReview.Application.Findings;

/// <summary>
/// Bounded scan conclusion. Describes what the scan can assert given its
/// coverage completeness and detected findings.
/// </summary>
public enum ScanConclusion
{
    /// <summary>Zero findings and all planned units successfully covered.</summary>
    NoRiskFoundWithinSuccessfulCoverage,

    /// <summary>Findings detected within covered scope.</summary>
    RisksFound,

    /// <summary>Scan is incomplete — coverage gaps, unresolved semantics, or cancellation exist.</summary>
    Incomplete,

    /// <summary>Task-level integrity failure — scan failed or was interrupted.</summary>
    Failed
}

/// <summary>
/// Result of concluding a scan — the enumerated conclusion plus a Chinese
/// display key for desktop/report rendering.
/// </summary>
public readonly record struct ConclusionResult(ScanConclusion Conclusion, string ChineseDisplayKey);
