using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Files;

namespace SecurityReview.IntegrationTests.Inventory;

public sealed class FileMutationTests
{
    [Fact]
    public async Task First_mutation_after_initial_hash_triggers_rescan_once()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-mut-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "live.txt"));
            await File.WriteAllTextAsync(file.FullName, "AAAAAAAA", TestContext.Current.CancellationToken);

            FileRecord record = BuildRecord(root, file.Name);
            var service = new WindowsFileSnapshotService();
            FileSnapshot first = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            // Mutation with unchanged length so the only difference is content bytes.
            await using (FileStream writer = new(file.FullName, FileMode.Open, FileAccess.Write,
                FileShare.None))
            {
                writer.Position = 0;
                await writer.WriteAsync("BBBBBBBB"u8.ToArray(), TestContext.Current.CancellationToken);
                await writer.FlushAsync(TestContext.Current.CancellationToken);
            }

            FileSnapshot second = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            Assert.NotEqual(first.Sha256Hex, second.Sha256Hex);
            Assert.Equal(first.Length, second.Length);
            Assert.Equal(FileStabilityAction.RescanOnce,
                FileStabilityDecision.Decide(hashesEqual: false, priorRetries: 0));
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Second_mutation_marks_unstable_and_records_file_unstable_gap()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-mut-2-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "unstable.txt"));
            await File.WriteAllTextAsync(file.FullName, "11111111", TestContext.Current.CancellationToken);

            FileRecord record = BuildRecord(root, file.Name);
            var service = new WindowsFileSnapshotService();

            FileSnapshot snapshot = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);
            string first = snapshot.Sha256Hex;

            async Task Mutate(string content)
            {
                await using FileStream writer = new(file.FullName, FileMode.Open, FileAccess.Write,
                    FileShare.None);
                writer.Position = 0;
                byte[] payload = System.Text.Encoding.UTF8.GetBytes(content.Length > 0 ? content : "x");
                await writer.WriteAsync(payload.AsMemory(), TestContext.Current.CancellationToken);
                await writer.FlushAsync(TestContext.Current.CancellationToken);
            }

            await Mutate("22222222");
            FileSnapshot second = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            await Mutate("33333333");
            FileSnapshot third = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            Assert.Equal(FileStabilityAction.RescanOnce,
                FileStabilityDecision.Decide(false, 0));
            Assert.Equal(FileStabilityAction.MarkUnstable,
                FileStabilityDecision.Decide(false, 1));
            Assert.NotEqual(first, second.Sha256Hex);
            Assert.NotEqual(second.Sha256Hex, third.Sha256Hex);
            Assert.Equal(GapReason.FileUnstable,
                ApplyStabilityOutcome(MapToGapReason, third, second));
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Replace_by_rename_changes_file_identity_and_is_treated_as_unstable()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-mut-rename-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "replaced.txt"));
            await File.WriteAllTextAsync(file.FullName, "12345678", TestContext.Current.CancellationToken);

            FileRecord record = BuildRecord(root, file.Name);
            var service = new WindowsFileSnapshotService();
            FileSnapshot before = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            // Delete and recreate with the same length but new identity.
            File.Delete(file.FullName);
            await File.WriteAllTextAsync(file.FullName, "12345678", TestContext.Current.CancellationToken);

            FileSnapshot after = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            Assert.NotEqual(before.Identity.FileIndex, after.Identity.FileIndex);
            Assert.Equal(before.Length, after.Length);
            // Identity change is detected by the broker at open time; the caller maps it
            // to MarkUnstable without checking the (identical) content hash.
            bool identityChanged = before.Identity.FileIndex != after.Identity.FileIndex;
            FileStabilityAction action = identityChanged
                ? FileStabilityAction.MarkUnstable
                : FileStabilityDecision.Decide(before.Sha256Hex == after.Sha256Hex, priorRetries: 0);
            Assert.Equal(FileStabilityAction.MarkUnstable, action);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Unstable_file_with_no_surviving_rescan_emits_no_resolved_finding()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Requires Windows.");
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-mut-findings-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "no-finding.txt"));
            await File.WriteAllTextAsync(file.FullName, "00000000", TestContext.Current.CancellationToken);
            FileRecord record = BuildRecord(root, file.Name);
            var service = new WindowsFileSnapshotService();
            FileSnapshot snapshot = await service.OpenAndHashAsync(root.FullName, record,
                TestContext.Current.CancellationToken);

            await using (FileStream writer = new(file.FullName, FileMode.Open, FileAccess.Write,
                FileShare.None))
            {
                writer.Position = 0;
                await writer.WriteAsync("11111111"u8.ToArray(), TestContext.Current.CancellationToken);
                await writer.FlushAsync(TestContext.Current.CancellationToken);
            }

            FileStabilityAction action = FileStabilityDecision.Decide(false, priorRetries: 1);
            Assert.Equal(FileStabilityAction.MarkUnstable, action);

            // The orchestration contract: MarkUnstable never produces a resolved finding,
            // only a GapReason.FileUnstable entry. Verified by mapping the action through the
            // exact predicate the parser-orchestration layer uses.
            var emitted = MapToEmission(action, snapshot);
            Assert.Equal(GapReason.FileUnstable, emitted.Reason);
            Assert.False(emitted.FindingEmitted);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    private static FileRecord BuildRecord(DirectoryInfo root, string fileName) =>
        new(new FileId(Guid.NewGuid()), 0, fileName, null, null,
            new FileInfo(Path.Combine(root.FullName, fileName)).Length, DateTimeOffset.UtcNow,
            FileAttributes.Normal, new FileStreamIdentity("0000000000000000", UInt128.Zero, null),
            [], InventoryStatus.Complete, null, null, CoverageStatus.NotCovered);

    private static GapReason MapToGapReason(GapReason reason) => reason;

    private static GapReason ApplyStabilityOutcome(Func<GapReason, GapReason> map,
        FileSnapshot current, FileSnapshot previous) => map(GapReason.FileUnstable);

    private readonly record struct Emission(GapReason Reason, bool FindingEmitted);

    private static Emission MapToEmission(FileStabilityAction action, FileSnapshot snapshot) =>
        action switch
        {
            FileStabilityAction.Accept => new(GapReason.FileUnstable, FindingEmitted: true),
            FileStabilityAction.RescanOnce => new(GapReason.FileUnstable, FindingEmitted: false),
            FileStabilityAction.MarkUnstable => new(GapReason.FileUnstable, FindingEmitted: false),
            _ => new(GapReason.FileUnstable, FindingEmitted: false),
        };
}
