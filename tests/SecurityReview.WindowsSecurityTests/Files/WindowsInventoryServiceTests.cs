using System.Diagnostics;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows.Files;
using SecurityReview.WindowsSecurityTests.Sandbox;

namespace SecurityReview.WindowsSecurityTests.Files;

public sealed class WindowsInventoryServiceTests
{
    private static readonly ScanId Scan = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));

    [Fact]
    public async Task enumerates_hidden_system_and_ads_without_following_reparse_points()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        Assert.Equal(InventoryOutcome.Completed, result.Outcome);
        Assert.Contains(result.Files, x => x.RelativePath == "hidden.txt");
        Assert.Contains(result.Files, x => x.RelativePath == "system.txt");
        Assert.Contains(result.Files, x => x.StreamName == "review-canary");
        Assert.DoesNotContain(result.Files,
            x => x.RelativePath.StartsWith("link-outside/", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Files,
            x => x.RelativePath.StartsWith("link-inside/", StringComparison.Ordinal));
        Assert.Contains(result.Gaps, x => x.Reason == GapReason.AccessDenied);
        Assert.Contains(result.BoundaryRecords,
            x => x.Code == InventoryBoundaryRecord.ReparsePointNotFollowed
                && x.RelativePath == "link-inside");
        Assert.Contains(result.BoundaryRecords,
            x => x.Code == InventoryBoundaryRecord.ReparsePointNotFollowed
                && x.RelativePath == "link-outside");
    }

    [Fact]
    public async Task ordering_is_ordinal_and_stable()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult first = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);
        InventoryResult second = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        Assert.Equal(first.Files.Select(x => x.InventoryKey),
            second.Files.Select(x => x.InventoryKey));
        Assert.Equal(first.Files.OrderBy(x => x.InventoryKey, StringComparer.Ordinal)
            .Select(x => x.InventoryKey), first.Files.Select(x => x.InventoryKey));

        // Stable identity: the same scan over unchanged files derives the same FileIds.
        Assert.Equal(first.Files.Select(x => x.FileId), second.Files.Select(x => x.FileId));
    }

    [Fact]
    public async Task metadata_units_cover_canaries_and_hidden_system_entries()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.DirectorySegment
            && x.Value == "canary-dir-xyz");
        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.FileName
            && x.Value == "plain.canaryx");
        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.Extension
            && x.Value == "canaryx");
        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.AdsName
            && x.Value == "review-canary");
        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.RelativePath
            && x.Value == "hidden.txt");
        Assert.Contains(result.MetadataUnits, x => x.Kind == InventoryMetadataKind.RelativePath
            && x.Value == "system.txt");
        Assert.All(result.MetadataUnits,
            x => Assert.IsType<Domain.Findings.SourceLocator.PathLocator>(x.Locator));
    }

    [Fact]
    public async Task component_asset_types_map_by_subtree()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        var allRelative = result.Files.Select(x => x.RelativePath).ToList();
        Assert.Contains(allRelative, x => x == "canary-dir-xyz/nested.txt");
        FileRecord nested = result.Files.First(x => x.RelativePath == "canary-dir-xyz/nested.txt");
        Assert.Contains(nested.ComponentAssetTypes, x => x.Value == "ASSET-001");
        // ordinary.txt and hardlink.txt share an identity; whichever the
        // enumerator visits first wins, the other becomes a boundary record.
        FileRecord unlinked = result.Files.First(x =>
            x.RelativePath is "ordinary.txt" or "hardlink.txt");
        Assert.Empty(unlinked.ComponentAssetTypes);
        Assert.Contains(result.BoundaryRecords,
            x => x.Code == InventoryBoundaryRecord.DuplicateIdentitySkipped);
    }

    [Fact]
    public async Task long_paths_beyond_260_characters_are_inventoried()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        FileRecord deep = Assert.Single(result.Files,
            x => x.RelativePath.EndsWith("file-long.txt", StringComparison.Ordinal));
        Assert.True((fixture.RootPath + "/" + deep.RelativePath).Length > 260);
    }

    [Fact]
    public async Task hardlink_duplicate_identity_is_recorded_once()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        var candidates = result.Files.Where(x =>
            x.RelativePath is "ordinary.txt" or "hardlink.txt").ToArray();
        Assert.Single(candidates);
        Assert.Contains(result.BoundaryRecords,
            x => x.Code == InventoryBoundaryRecord.DuplicateIdentitySkipped);
    }

    [Fact]
    public async Task diagnostics_never_contain_full_paths()
    {
        using InventoryFixture fixture = await InventoryFixture.CreateAsync();
        var service = new WindowsInventoryService();

        InventoryResult result = await service.BuildAsync(
            fixture.Request(Scan), TestContext.Current.CancellationToken);

        Assert.All(result.Gaps, gap =>
        {
            Assert.DoesNotContain(fixture.RootPath, gap.VirtualPath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(":\\", gap.VirtualPath, StringComparison.Ordinal);
            Assert.DoesNotContain(":\\", gap.DetailCode, StringComparison.Ordinal);
        });
        Assert.All(result.BoundaryRecords, record =>
            Assert.DoesNotContain(":\\", record.RelativePath, StringComparison.Ordinal));
    }

    [Fact]
    public async Task input_scope_accepts_exact_limit_and_rejects_one_over()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-inv-scope-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "one.txt"), "x", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "two.txt"), "yy", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "two.txt") + ":s1", "zzz", TestContext.Current.CancellationToken);
            var service = new WindowsInventoryService();
            CancellationToken ct = TestContext.Current.CancellationToken;

            InventoryResult exact = await service.BuildAsync(
                new InventoryRequest(Scan, root.FullName, [], 3, InventoryRequest.DefaultMaxTotalBytes), ct);
            Assert.Equal(InventoryOutcome.Completed, exact.Outcome);
            Assert.Equal(3, exact.ObservedStreamCount);

            InventoryResult over = await service.BuildAsync(
                new InventoryRequest(Scan, root.FullName, [], 2, InventoryRequest.DefaultMaxTotalBytes), ct);
            Assert.Equal(InventoryOutcome.InputScopeExceeded, over.Outcome);
            Assert.Equal(InventoryFailureCodes.InputScopeExceeded, over.FailureCode);
            Assert.Empty(over.Files);
            Assert.Equal(3, over.ObservedStreamCount);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    private sealed class InventoryFixture : IDisposable
    {
        private InventoryFixture(DirectoryInfo baseDir, string rootPath)
        {
            BaseDir = baseDir;
            RootPath = rootPath;
        }

        private DirectoryInfo BaseDir { get; }
        public string RootPath { get; }

        public InventoryRequest Request(ScanId scanId) =>
            InventoryRequest.Create(Scan, RootPath,
                [AssetComponent.Create("canary-dir-xyz", AssetTypeId.Parse("ASSET-001"))]);

        public static async Task<InventoryFixture> CreateAsync()
        {
            WindowsSecurityGate.AssertEnabled();
            DirectoryInfo baseDir = Directory.CreateTempSubdirectory("srt-inv-");
            string root = Path.Combine(baseDir.FullName, "scan");
            string outside = Path.Combine(baseDir.FullName, "outside");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(outside);
            await File.WriteAllTextAsync(Path.Combine(outside, "escaped.txt"), "outside", TestContext.Current.CancellationToken);

            await File.WriteAllTextAsync(Path.Combine(root, "ordinary.txt"), "ordinary", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "hidden.txt"), "hidden", TestContext.Current.CancellationToken);
            File.SetAttributes(Path.Combine(root, "hidden.txt"), FileAttributes.Hidden);
            await File.WriteAllTextAsync(Path.Combine(root, "system.txt"), "system", TestContext.Current.CancellationToken);
            File.SetAttributes(Path.Combine(root, "system.txt"),
                FileAttributes.System | FileAttributes.Hidden);
            await File.WriteAllTextAsync(Path.Combine(root, "plain.canaryx"), "ext", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "ads.txt"), "default-stream", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "ads.txt") + ":review-canary", "ads-canary", TestContext.Current.CancellationToken);

            string canaryDir = Path.Combine(root, "canary-dir-xyz");
            Directory.CreateDirectory(canaryDir);
            await File.WriteAllTextAsync(Path.Combine(canaryDir, "nested.txt"), "nested", TestContext.Current.CancellationToken);

            string deep = root;
            for (int i = 0; i < 4; i++)
            {
                deep = Path.Combine(deep, new string('d', 60));
            }

            Directory.CreateDirectory(deep);
            await File.WriteAllTextAsync(Path.Combine(deep, "file-long.txt"), "long", TestContext.Current.CancellationToken);

            string denied = Path.Combine(root, "denied");
            Directory.CreateDirectory(denied);
            await File.WriteAllTextAsync(Path.Combine(denied, "secret.txt"), "secret", TestContext.Current.CancellationToken);
            string principal = Environment.UserDomainName + "\\" + Environment.UserName;
            await RunAsync("icacls.exe",
                $"\"{denied}\" /deny \"{principal}:(OI)(CI)(RD)\"");

            await RunAsync("cmd.exe",
                $"/c mklink /H \"{Path.Combine(root, "hardlink.txt")}\" \"{Path.Combine(root, "ordinary.txt")}\"");
            await RunAsync("cmd.exe",
                $"/c mklink /J \"{Path.Combine(root, "link-inside")}\" \"{canaryDir}\"");
            await RunAsync("cmd.exe",
                $"/c mklink /J \"{Path.Combine(root, "link-outside")}\" \"{outside}\"");

            return new InventoryFixture(baseDir, root);
        }

        private static async Task RunAsync(string fileName, string arguments)
        {
            using Process process = Process.Start(new ProcessStartInfo(fileName, arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true,
            })!;
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            Assert.True(process.ExitCode == 0, $"{fileName} {arguments} failed: {error}");
        }

        public void Dispose()
        {
            try
            {
                using Process process = Process.Start(new ProcessStartInfo("icacls.exe",
                    $"\"{BaseDir.FullName}\" /reset /t /c /q")
                { CreateNoWindow = true })!;
                process.WaitForExit(10_000);
                BaseDir.Refresh();
                BaseDir.Delete(recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
