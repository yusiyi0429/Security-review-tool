using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Rules;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanQueryServiceTests
{
    [Fact]
    public async Task Occurrence_projection_and_detail_use_real_scan_scoped_records()
    {
        ScanId scanId = new(Guid.NewGuid());
        FindingGroupId groupId = new(Guid.NewGuid());
        FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "raw-secret",
            "raw-context",
            new SourceLocator.TextLocator(2, 3, 10, 4),
            "folder/private/file.json",
            new string('a', 64),
            [
                new FindingProvenance(
                    new DetectorId("DET-1"),
                    new RuleId("RULE-1"),
                    DetectionConfidence.High,
                    false),
            ]);
        var group = new FindingGroup(
            groupId,
            FindingKind.SensitiveContent,
            Severity.High,
            new ValueFingerprint(new string('b', 64)),
            [occurrence]);
        ScanQueryService query = CreateQuery(
            scanId,
            [group],
            []);

        PagedResult<FindingOccurrenceSummary> page =
            await query.GetOccurrencesPagedAsync(groupId, 0);
        FindingOccurrenceSummary summary = Assert.Single(page.Items);
        Assert.Equal(occurrenceId, summary.OccurrenceId);
        Assert.Equal("…/file.json", summary.RedactedVirtualPath);
        Assert.Equal("text:2:3@10+4", summary.LocatorDisplay);

        DisposableOccurrenceDetail? detail = await query
            .GetOccurrenceDetailsAsync(scanId, occurrenceId);
        Assert.NotNull(detail);
        try
        {
            Assert.Equal("raw-secret", detail.SensitiveValue.Value);
            Assert.Equal("raw-context", detail.SensitiveContext.Value);
        }
        finally
        {
            detail.SensitiveValue.Dispose();
            detail.SensitiveContext.Dispose();
        }
    }

    [Fact]
    public async Task File_projection_preserves_identity_format_and_coverage()
    {
        ScanId scanId = new(Guid.NewGuid());
        FileId fileId = new(Guid.NewGuid());
        var file = new FileRecord(
            fileId,
            0,
            "folder/file.md",
            null,
            null,
            123,
            DateTimeOffset.UnixEpoch,
            FileAttributes.Normal,
            new FileStreamIdentity("volume", 1, null),
            Array.Empty<AssetTypeId>(),
            InventoryStatus.Complete,
            "text",
            new string('c', 64),
            CoverageStatus.Covered);
        ScanQueryService query = CreateQuery(
            scanId,
            [],
            [file]);

        PagedResult<CoverageFileSummary> page =
            await query.GetFilesPagedAsync(scanId, 0);
        CoverageFileSummary summary = Assert.Single(page.Items);
        Assert.Equal(fileId, summary.FileId);
        Assert.Equal("root-1/…/file.md", summary.RedactedPath);
        Assert.Equal("text", summary.FormatId);
        Assert.Equal(CoverageStatus.Covered, summary.Coverage);
        Assert.Equal(new string('c', 12), summary.ContentHashPrefix);
    }

    private static ScanQueryService CreateQuery(
        ScanId scanId,
        IReadOnlyList<FindingGroup> groups,
        IReadOnlyList<FileRecord> files)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId,
            ScanStatus.Completed,
            now,
            now,
            "rules",
            "client",
            "pipeline",
            files.Count,
            1);
        return new ScanQueryService(
            new FakeScanRepository(scan),
            new FakeFindingRepository(scanId, groups),
            new FakeCoverageRepository(),
            new FakeFileRepository(scanId, files),
            new FakeReviewService());
    }

    private sealed class FakeScanRepository(ScanRun scan) : IScanRepository
    {
        public Task InsertAsync(ScanRun value, CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<ScanRun?> GetByIdAsync(
            ScanId scanId,
            CancellationToken ct = default)
            => Task.FromResult<ScanRun?>(scan.ScanId == scanId ? scan : null);

        public Task<IReadOnlyList<ScanRun>> ListAsync(
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<ScanRun>>([scan]);

        public Task<bool> TryTransitionAsync(
            ScanId scanId,
            ScanStatus expectedStatus,
            long expectedVersion,
            ScanStatus nextStatus,
            CancellationToken ct = default)
            => Task.FromResult(false);

        public Task UpdateAsync(ScanRun value, CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<ScanRun>> ListByStatusAsync(
            IReadOnlyList<ScanStatus> statuses,
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<ScanRun>>(
                statuses.Contains(scan.Status) ? [scan] : []);

        public Task<ScanRun?> FindLatestPreviousAsync(
            string activeRulePackHash,
            string endpointFingerprint,
            CancellationToken ct = default)
            => Task.FromResult<ScanRun?>(scan);
    }

    private sealed class FakeFindingRepository(
        ScanId scanId,
        IReadOnlyList<FindingGroup> groups) : IFindingRepository
    {
        public Task InsertGroupAsync(
            ScanId id,
            FindingGroup group,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task InsertOccurrenceAsync(
            FileId fileId,
            FindingOccurrence occurrence,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task InsertOccurrenceBatchAsync(
            FileId fileId,
            IReadOnlyList<FindingOccurrence> occurrences,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<FindingGroup?> GetGroupByIdAsync(
            FindingGroupId id,
            CancellationToken ct = default)
            => Task.FromResult(groups.FirstOrDefault(group => group.Id == id));

        public Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(
            ScanId id,
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<FindingGroup>>(
                id == scanId ? groups : []);

        public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(
            FindingGroupId groupId,
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<FindingOccurrence>>(
                groups.FirstOrDefault(group => group.Id == groupId)?.Occurrences
                ?? []);
    }

    private sealed class FakeCoverageRepository : ICoverageRepository
    {
        public Task InsertAsync(CoverageGap gap, CancellationToken ct = default)
            => Task.CompletedTask;

        public Task InsertBatchAsync(
            IReadOnlyList<CoverageGap> gaps,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(
            ScanId scanId,
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<CoverageGap>>([]);
    }

    private sealed class FakeFileRepository(
        ScanId scanId,
        IReadOnlyList<FileRecord> files) : IFileRepository
    {
        public Task InsertAsync(
            ScanId id,
            FileRecord file,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task InsertBatchAsync(
            ScanId id,
            IReadOnlyList<FileRecord> values,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task UpdateAsync(
            ScanId id,
            FileRecord file,
            CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<FileRecord?> GetByIdAsync(
            FileId fileId,
            CancellationToken ct = default)
            => Task.FromResult(files.FirstOrDefault(file => file.FileId == fileId));

        public Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(
            ScanId id,
            CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<FileRecord>>(
                id == scanId ? files : []);

        public Task<int> CountByScanIdAsync(
            ScanId id,
            CancellationToken ct = default)
            => Task.FromResult(id == scanId ? files.Count : 0);
    }

    private sealed class FakeReviewService : IReviewService
    {
        public Task<ReviewDecision> RecordReviewAsync(
            RecordReviewCommand command,
            CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<ExceptionGrant> GrantExceptionAsync(
            GrantExceptionCommand command,
            CancellationToken ct = default)
            => throw new NotSupportedException();

        public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
            FindingOccurrenceId occurrenceId,
            string assetBindingHmac,
            string occurrenceBindingHmac,
            CancellationToken ct = default)
            => Task.FromResult(new EffectiveReviewResult(
                SecurityReview.Domain.Reviews.ReviewStatus.Pending,
                "pending",
                null));
    }
}
