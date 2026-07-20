using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class CoverageSummaryTests
{
    [Fact]
    public void All_planned_units_covered_can_complete()
    {
        var summary = CoverageSummary.Create(plannedUnits: 3, coveredUnits: 3, gaps: []);
        Assert.Equal(CoverageStatus.Covered, summary.Status);
        Assert.Equal(ScanStatus.Completed, summary.FinalScanStatus(unresolvedSemanticCandidates: 0));
    }

    [Fact]
    public void Any_gap_forces_partial()
    {
        var gap = CoverageGap.CreateForTest(GapReason.ParserTimeout);
        var summary = CoverageSummary.Create(3, 2, [gap]);
        Assert.Equal(CoverageStatus.PartiallyCovered, summary.Status);
        Assert.Equal(ScanStatus.Partial, summary.FinalScanStatus(0));
    }

    [Fact]
    public void Unresolved_semantic_candidate_forces_partial()
    {
        var summary = CoverageSummary.Create(1, 1, []);
        Assert.Equal(ScanStatus.Partial, summary.FinalScanStatus(1));
    }
}
