using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Findings;

/// <summary>
/// Calculates a bounded scan conclusion from scan status, coverage summary,
/// unresolved semantic candidate count, and total finding count. No conclusion
/// text ever contains "Safe", "Guaranteed", or "ApprovedForRelease".
/// </summary>
public static class ConclusionCalculator
{
    public static ConclusionResult Calculate(
        ScanStatus scanStatus,
        CoverageSummary coverageSummary,
        int unresolvedSemanticCount,
        int findingCount)
    {
        // Task-level integrity failures take precedence
        if (scanStatus == ScanStatus.Failed || scanStatus == ScanStatus.Interrupted)
        {
            return new ConclusionResult(ScanConclusion.Failed, "conclusion_failed");
        }

        // Any gap, cancellation, or unresolved semantic → incomplete
        bool hasGaps = coverageSummary.Gaps.Count > 0;
        bool hasUnresolved = unresolvedSemanticCount > 0;
        bool isCancelled = scanStatus == ScanStatus.Cancelled || scanStatus == ScanStatus.Cancelling;
        bool isPartial = scanStatus == ScanStatus.Partial;

        if (hasGaps || hasUnresolved || isCancelled || isPartial)
        {
            return new ConclusionResult(ScanConclusion.Incomplete, "conclusion_incomplete");
        }

        // All covered — the only remaining question is whether findings exist
        if (findingCount > 0)
        {
            return new ConclusionResult(ScanConclusion.RisksFound, "conclusion_risks_found");
        }

        return new ConclusionResult(
            ScanConclusion.NoRiskFoundWithinSuccessfulCoverage,
            "conclusion_no_risk_within_coverage");
    }
}
