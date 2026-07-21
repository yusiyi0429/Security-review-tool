using SecurityReview.Application.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Findings;

public sealed class ConclusionCalculatorTests
{
    // ---------- Zero findings, all covered → NoRiskFoundWithinSuccessfulCoverage ----------

    [Fact]
    public void Zero_findings_all_covered_returns_no_risk_within_coverage()
    {
        var summary = CoverageSummary.Create(plannedUnits: 5, coveredUnits: 5, gaps: []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, unresolvedSemanticCount: 0, findingCount: 0);

        Assert.Equal(ScanConclusion.NoRiskFoundWithinSuccessfulCoverage, result.Conclusion);
        Assert.NotEmpty(result.ChineseDisplayKey);
    }

    // ---------- Findings, all covered → RisksFound ----------

    [Fact]
    public void Findings_all_covered_returns_risks_found()
    {
        var summary = CoverageSummary.Create(5, 5, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, 0, findingCount: 3);

        Assert.Equal(ScanConclusion.RisksFound, result.Conclusion);
        Assert.NotEmpty(result.ChineseDisplayKey);
    }

    // ---------- Any gap → Incomplete ----------

    [Fact]
    public void Coverage_gap_makes_incomplete()
    {
        var gap = CoverageGap.CreateForTest(GapReason.AccessDenied);
        var summary = CoverageSummary.Create(5, 4, [gap]);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, 0, findingCount: 1);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    [Fact]
    public void User_excluded_makes_incomplete()
    {
        var gap = CoverageGap.CreateForTest(GapReason.UserExcluded);
        var summary = CoverageSummary.Create(5, 4, [gap]);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    [Fact]
    public void Encrypted_gap_makes_incomplete()
    {
        var gap = CoverageGap.CreateForTest(GapReason.Encrypted);
        var summary = CoverageSummary.Create(5, 4, [gap]);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    [Fact]
    public void File_unstable_gap_makes_incomplete()
    {
        var gap = CoverageGap.CreateForTest(GapReason.FileUnstable);
        var summary = CoverageSummary.Create(5, 4, [gap]);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    // ---------- Unresolved semantic → Incomplete ----------

    [Fact]
    public void Unresolved_semantic_makes_incomplete()
    {
        var summary = CoverageSummary.Create(5, 5, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Completed, summary, unresolvedSemanticCount: 2, findingCount: 5);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    // ---------- Cancelled → Incomplete ----------

    [Fact]
    public void Cancelled_is_incomplete()
    {
        var summary = CoverageSummary.Create(5, 3, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Cancelled, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }

    // ---------- Task-level integrity failure → Failed ----------

    [Fact]
    public void Scan_failed_returns_failed()
    {
        var summary = CoverageSummary.Create(5, 0, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Failed, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Failed, result.Conclusion);
    }

    [Fact]
    public void Scan_interrupted_returns_failed()
    {
        var summary = CoverageSummary.Create(5, 0, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Interrupted, summary, 0, findingCount: 0);

        Assert.Equal(ScanConclusion.Failed, result.Conclusion);
    }

    // ---------- No forbidden enum/text ----------

    [Fact]
    public void No_enum_member_contains_forbidden_terms()
    {
        foreach (var name in Enum.GetNames<ScanConclusion>())
        {
            Assert.DoesNotContain("Safe", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Guaranteed", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("ApprovedForRelease", name, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Chinese_display_keys_produced_for_all_conclusions()
    {
        foreach (var conclusion in Enum.GetValues<ScanConclusion>())
        {
            var result = ConclusionCalculator.Calculate(
                ScanStatus.Completed,
                CoverageSummary.Create(1, 1, []),
                0, conclusion == ScanConclusion.RisksFound ? 3 : 0);

            Assert.NotEmpty(result.ChineseDisplayKey);
        }
    }

    // ---------- Partial status with no gaps and findings covered → Incomplete (not completed) ----------

    [Fact]
    public void Partial_status_always_incomplete_regardless_of_coverage()
    {
        var summary = CoverageSummary.Create(5, 5, []);
        var result = ConclusionCalculator.Calculate(
            ScanStatus.Partial, summary, 0, findingCount: 3);

        Assert.Equal(ScanConclusion.Incomplete, result.Conclusion);
    }
}
