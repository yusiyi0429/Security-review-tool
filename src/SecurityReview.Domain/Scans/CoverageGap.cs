namespace SecurityReview.Domain.Scans;

public sealed record CoverageGap(
    Guid GapId, ScanId ScanId, FileId? FileId, string VirtualPath, string FormatId,
    string Stage, GapReason Reason, string DetailCode, long? PlannedBytes,
    long? ProcessedBytes, DateTimeOffset CreatedAtUtc)
{
    public static CoverageGap CreateForTest(GapReason reason) =>
        new(Guid.NewGuid(), new ScanId(Guid.Empty), null, "synthetic", "test", "test",
            reason, "synthetic", 1, 0, DateTimeOffset.UnixEpoch);
}
