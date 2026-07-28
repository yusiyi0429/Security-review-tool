using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
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

    [Fact]
    public async Task File_location_resolves_absolute_path_from_root_index()
    {
        ScanId scanId = new(Guid.NewGuid());
        FindingGroupId groupId = new(Guid.NewGuid());
        FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
        string fileHash = new string('a', 64);
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "raw-secret",
            "raw-context",
            new SourceLocator.TextLocator(0, 0, 10, 4),
            "conf/app.json",
            fileHash,
            []);
        var group = new FindingGroup(
            groupId,
            FindingKind.SensitiveContent,
            Severity.High,
            new ValueFingerprint(new string('b', 64)),
            [occurrence]);
        var file = new FileRecord(
            new FileId(Guid.NewGuid()),
            1,
            "conf/app.json",
            null,
            null,
            128,
            DateTimeOffset.UnixEpoch,
            FileAttributes.Normal,
            new FileStreamIdentity("volume", 1, null),
            [],
            InventoryStatus.Complete,
            "json",
            fileHash,
            CoverageStatus.Covered);
        var protector = new FakePayloadProtector();
        ScanQueryService query = CreateQuery(
            scanId,
            [group],
            [file],
            ScanTestData.BuildRecord(
                scanId, protector, "C:\\root-a", "D:\\root-b"));

        OccurrenceFileLocation? location =
            await query.GetOccurrenceFileLocationAsync(scanId, occurrenceId);

        Assert.NotNull(location);
        Assert.Equal(
            Path.GetFullPath(Path.Combine("D:\\root-b", "conf/app.json")),
            location.AbsolutePath);
        Assert.Equal("conf/app.json", location.VirtualPath);
        Assert.False(location.IsNested);
        Assert.False(location.FileExists); // 测试机上该路径不存在
    }

    [Fact]
    public async Task File_location_marks_nested_content_and_resolves_outer_container()
    {
        ScanId scanId = new(Guid.NewGuid());
        FindingGroupId groupId = new(Guid.NewGuid());
        FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
        string fileHash = new string('c', 64);
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "raw-secret",
            "raw-context",
            new SourceLocator.NestedLocator(
                "bundle.zip",
                new SourceLocator.TextLocator(0, 0, 3, 6)),
            "bundle.zip!inner/secret.txt",
            fileHash,
            []);
        var group = new FindingGroup(
            groupId,
            FindingKind.SensitiveContent,
            Severity.High,
            new ValueFingerprint(new string('d', 64)),
            [occurrence]);
        var file = new FileRecord(
            new FileId(Guid.NewGuid()),
            0,
            "bundle.zip",
            null,
            null,
            4096,
            DateTimeOffset.UnixEpoch,
            FileAttributes.Normal,
            new FileStreamIdentity("volume", 1, null),
            [],
            InventoryStatus.Complete,
            "zip",
            fileHash,
            CoverageStatus.Covered);
        var protector = new FakePayloadProtector();
        ScanQueryService query = CreateQuery(
            scanId,
            [group],
            [file],
            ScanTestData.BuildRecord(scanId, protector, "E:\\scans"));

        OccurrenceFileLocation? location =
            await query.GetOccurrenceFileLocationAsync(scanId, occurrenceId);

        Assert.NotNull(location);
        Assert.True(location.IsNested);
        Assert.Equal("bundle.zip", location.OuterVirtualPath);
        Assert.Equal(
            Path.GetFullPath(Path.Combine("E:\\scans", "bundle.zip")),
            location.AbsolutePath);
    }

    [Fact]
    public async Task File_location_is_scoped_to_the_requested_scan()
    {
        ScanId scanId = new(Guid.NewGuid());
        FindingGroupId groupId = new(Guid.NewGuid());
        FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "raw-secret",
            "raw-context",
            new SourceLocator.TextLocator(0, 0, 0, 4),
            "conf/app.json",
            new string('a', 64),
            []);
        var group = new FindingGroup(
            groupId,
            FindingKind.SensitiveContent,
            Severity.High,
            new ValueFingerprint(new string('b', 64)),
            [occurrence]);
        ScanQueryService query = CreateQuery(scanId, [group], []);

        Assert.Null(await query.GetOccurrenceFileLocationAsync(
            new ScanId(Guid.NewGuid()), occurrenceId));
    }

    private static ScanQueryService CreateQuery(
        ScanId scanId,
        IReadOnlyList<FindingGroup> groups,
        IReadOnlyList<FileRecord> files,
        ScanSnapshotRecord? snapshotRecord = null)
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
            new FakeReviewService(),
            new FakeScanSnapshotRepository(snapshotRecord),
            new FakePayloadProtector());
    }
}
