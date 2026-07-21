using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows.Files;

namespace SecurityReview.IntegrationTests.Inventory;

public sealed class InventoryCoverageTests
{
    private static readonly ScanId Scan = new(Guid.Parse("11111111-1111-1111-1111-111111111111"));

    private static FileStreamIdentity Identity(string? stream = null) =>
        new("A0B1C2D3", (UInt128)0x1234, stream);

    private static FileRecord Record(string relativePath, string? streamName = null) =>
        new(new FileId(Guid.NewGuid()), 0, relativePath, null, streamName, 10,
            DateTimeOffset.UnixEpoch, FileAttributes.Normal, Identity(streamName),
            [], InventoryStatus.Complete, null, null, CoverageStatus.NotCovered);

    [Fact]
    public void identity_derives_deterministic_uuidv5_scoped_to_scan()
    {
        FileStreamIdentity identity = new("A0B1C2D3", (UInt128)42, "review-canary");

        FileId first = identity.DeriveFileId(Scan);
        FileId second = identity.DeriveFileId(Scan);
        FileId otherScan = identity.DeriveFileId(new ScanId(Guid.NewGuid()));
        FileId otherStream = Identity("other").DeriveFileId(Scan);

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherScan);
        Assert.NotEqual(first, otherStream);
        // RFC 4122 version 5 and variant bits.
        byte[] bytes = first.Value.ToByteArray();
        Assert.Equal(5, bytes[7] >> 4);
        Assert.Equal(0b10, bytes[8] >> 6);
    }

    [Fact]
    public void metadata_unit_rejects_overlong_value()
    {
        string value = new('a', InventoryMetadataUnit.MaxValueUtf16Units + 1);
        Assert.Null(InventoryMetadataUnit.TryCreate(new FileId(Guid.NewGuid()),
            InventoryMetadataKind.RelativePath, value,
            new SourceLocator.PathLocator(PathKind.Segment, "x")));
    }

    [Fact]
    public void metadata_unit_rejects_malformed_unicode()
    {
        string value = "abc" + (char)0xD800 + "def";
        Assert.Null(InventoryMetadataUnit.TryCreate(new FileId(Guid.NewGuid()),
            InventoryMetadataKind.FileName, value,
            new SourceLocator.PathLocator(PathKind.Segment, "x")));
    }

    [Fact]
    public void metadata_unit_accepts_exact_limit_value()
    {
        string value = new('a', InventoryMetadataUnit.MaxValueUtf16Units);
        Assert.NotNull(InventoryMetadataUnit.TryCreate(new FileId(Guid.NewGuid()),
            InventoryMetadataKind.Extension, value,
            new SourceLocator.PathLocator(PathKind.Segment, "x")));
    }

    [Fact]
    public void ordering_is_root_then_ordinal_path_then_ordinal_stream()
    {
        FileRecord[] unordered =
        [
            Record("b.txt"),
            Record("a.txt", "z"),
            Record("a.txt", "a"),
            Record("a.txt"),
            Record("A.txt"),
        ];

        string[] ordered = InventoryOrdering.Order(unordered)
            .Select(x => x.InventoryKey).ToArray();

        Assert.Equal(
            ["0|A.txt|", "0|a.txt|", "0|a.txt|a", "0|a.txt|z", "0|b.txt|"],
            ordered);
    }

    [Fact]
    public void stream_budget_accepts_exact_limits()
    {
        var budget = new StreamBudgetAccumulator(maxStreams: 3, maxTotalBytes: 1_000);
        Assert.True(budget.TryAdd(400));
        Assert.True(budget.TryAdd(400));
        Assert.True(budget.TryAdd(200));
        Assert.Equal(3, budget.StreamCount);
        Assert.Equal(1_000, budget.TotalBytes);
    }

    [Fact]
    public void stream_budget_rejects_one_over_stream_limit()
    {
        var budget = new StreamBudgetAccumulator(maxStreams: 2, maxTotalBytes: long.MaxValue);
        Assert.True(budget.TryAdd(1));
        Assert.True(budget.TryAdd(1));
        Assert.False(budget.TryAdd(1));
    }

    [Fact]
    public void stream_budget_rejects_one_over_byte_limit()
    {
        var budget = new StreamBudgetAccumulator(maxStreams: 10, maxTotalBytes: 1_000);
        Assert.True(budget.TryAdd(1_000));
        Assert.False(budget.TryAdd(1));
    }

    [Fact]
    public void stream_budget_rejects_overflowing_metadata_without_wrapping()
    {
        var budget = new StreamBudgetAccumulator(maxStreams: 10, maxTotalBytes: long.MaxValue);
        Assert.True(budget.TryAdd(long.MaxValue));
        Assert.False(budget.TryAdd(1));
        Assert.Equal(long.MaxValue, budget.TotalBytes);
    }

    [Fact]
    public async Task non_ntfs_volume_reports_no_ads_capability_and_skips_enumeration()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-inv-fat-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "plain.txt"), "x", TestContext.Current.CancellationToken);

            var service = new WindowsInventoryService(_ => "FAT32");
            InventoryResult result = await service.BuildAsync(
                InventoryRequest.Create(Scan, root.FullName),
                TestContext.Current.CancellationToken);

            Assert.Equal(InventoryOutcome.Completed, result.Outcome);
            Assert.Equal(AdsCapability.NotAvailableForFileSystem, result.AdsCapability);
            Assert.Single(result.Files);
            Assert.Null(result.Files[0].StreamName);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task unidentifiable_root_is_task_failure_not_empty_inventory()
    {
        string missing = Path.Combine(Path.GetTempPath(),
            "srt-inv-missing-" + Guid.NewGuid().ToString("N"));
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            InventoryRequest.Create(Scan, missing), TestContext.Current.CancellationToken);

        Assert.Equal(InventoryOutcome.RootFailed, result.Outcome);
        Assert.Equal(InventoryFailureCodes.RootUnavailable, result.FailureCode);
        Assert.Empty(result.Files);
    }

    [Fact]
    public async Task sparse_inputs_over_10gib_stop_with_input_scope_exceeded()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-inv-sparse-");
        try
        {
            await using (FileStream first = new(Path.Combine(root.FullName, "a.bin"),
                FileMode.Create, FileAccess.Write, FileShare.None))
            {
                first.SetLength(5L * 1024 * 1024 * 1024);
            }

            await using (FileStream second = new(Path.Combine(root.FullName, "b.bin"),
                FileMode.Create, FileAccess.Write, FileShare.None))
            {
                second.SetLength(6L * 1024 * 1024 * 1024);
            }

            var service = new WindowsInventoryService();
            InventoryResult result = await service.BuildAsync(
                InventoryRequest.Create(Scan, root.FullName),
                TestContext.Current.CancellationToken);

            Assert.Equal(InventoryOutcome.InputScopeExceeded, result.Outcome);
            Assert.Equal(InventoryFailureCodes.InputScopeExceeded, result.FailureCode);
            Assert.True(result.ObservedTotalBytes > InventoryRequest.DefaultMaxTotalBytes);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }
}
