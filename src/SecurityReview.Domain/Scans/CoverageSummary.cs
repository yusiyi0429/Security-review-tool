namespace SecurityReview.Domain.Scans;

public sealed record CoverageSummary(int PlannedUnits, int CoveredUnits,
    IReadOnlyList<CoverageGap> Gaps, CoverageStatus Status)
{
    public static CoverageSummary Create(int plannedUnits, int coveredUnits, IReadOnlyList<CoverageGap> gaps)
    {
        if (plannedUnits < 0 || coveredUnits < 0 || coveredUnits > plannedUnits)
        {
            throw new ArgumentOutOfRangeException(nameof(coveredUnits));
        }

        CoverageStatus status = gaps.Count == 0 && coveredUnits == plannedUnits
            ? CoverageStatus.Covered
            : coveredUnits == 0 ? CoverageStatus.NotCovered : CoverageStatus.PartiallyCovered;
        return new(plannedUnits, coveredUnits, gaps, status);
    }

    public ScanStatus FinalScanStatus(int unresolvedSemanticCandidates) =>
        Status == CoverageStatus.Covered && unresolvedSemanticCandidates == 0
            ? ScanStatus.Completed
            : ScanStatus.Partial;
}
