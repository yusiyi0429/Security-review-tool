using System.IO.Pipes;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Files;
using SecurityReview.WindowsSecurityTests.Sandbox;

namespace SecurityReview.WindowsSecurityTests.Files;

public sealed class WindowsReadOnlyFileBrokerTests
{
    [Fact]
    public async Task Open_acquires_read_only_handle_and_reports_stable_snapshot()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "plain.txt"));
            await File.WriteAllTextAsync(file.FullName, "hello", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle =
                await broker.OpenAsync(root.FullName, BuildRecord(root.FullName, file.Name),
                    TestContext.Current.CancellationToken);

            Assert.Equal(5L, handle.InitialSnapshot.Length);
            string hex = handle.InitialSnapshot.Sha256Hex;
            Assert.Equal(64, hex.Length);
            Assert.True(hex.All(c => "0123456789abcdef".Contains(c)), "sha hex must be lowercase hex");
            Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                hex, ignoreCase: true);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_rejects_write_attempts_through_brokered_handle()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-ro-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "ro.txt"));
            await File.WriteAllTextAsync(file.FullName, "read-only", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle =
                await broker.OpenAsync(root.FullName, BuildRecord(root.FullName, file.Name),
                    TestContext.Current.CancellationToken);

            // The handle's native access mask must not include write bits: trying to write
            // through a FileStream wrapping the handle fails at the first I/O.
            Assert.ThrowsAny<Exception>(() =>
            {
                using FileStream fs = new(handle.Handle, FileAccess.Write);
                fs.WriteByte(0);
                fs.Flush();
            });
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_uses_query_identity_and_size_from_handle_not_from_path_metadata()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-id-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "id.txt"));
            await File.WriteAllTextAsync(file.FullName, "identity-content", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle =
                await broker.OpenAsync(root.FullName, BuildRecord(root.FullName, file.Name),
                    TestContext.Current.CancellationToken);

            Assert.Equal(file.Length, handle.InitialSnapshot.Length);
            Assert.Equal(new FileInfo(Path.Combine(root.FullName, file.Name)).LastWriteTimeUtc,
                handle.InitialSnapshot.LastWriteUtc, TimeSpan.FromSeconds(2));
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_default_stream_returns_redacted_display_id()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-disp-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "display.txt"));
            await File.WriteAllTextAsync(file.FullName, "display", TestContext.Current.CancellationToken);
            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle =
                await broker.OpenAsync(root.FullName, BuildRecord(root.FullName, file.Name),
                    TestContext.Current.CancellationToken);

            Assert.Equal(12, handle.DisplayId.Length);
            Assert.True(handle.DisplayId.All(c => "0123456789abcdef".Contains(c)));
            Assert.NotEqual(Guid.Empty.ToString("N"), handle.DisplayId);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_alternate_data_stream_succeeds_and_stream_path_is_constructed_in_broker()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-ads-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "ads.txt"));
            await File.WriteAllTextAsync(file.FullName, "default-stream", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(file.FullName + ":review-canary", "ads-content", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle = await broker.OpenAsync(
                root.FullName,
                BuildRecord(root.FullName, file.Name, streamName: "review-canary"),
                TestContext.Current.CancellationToken);

            Assert.Equal("review-canary", handle.InitialSnapshot.Identity.StreamName);
            Assert.Equal("ads-content"u8.Length, handle.InitialSnapshot.Length);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_rejects_ads_names_with_separator_colon_or_nul()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-ads-bad-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "a.txt"));
            await File.WriteAllTextAsync(file.FullName, "x", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            foreach (string bad in new[] { "name:with-colon", "name\\with-slash", "name/with-fwd", "name\0null", "name.with.dot" })
            {
                await Assert.ThrowsAnyAsync<Exception>(() =>
                    broker.OpenAsync(root.FullName,
                        BuildRecord(root.FullName, file.Name, streamName: bad),
                        TestContext.Current.CancellationToken));
            }
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Open_retries_on_sharing_violation_until_access_denied_then_surfaces_typed_failure()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-share-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "shared.txt"));
            await File.WriteAllTextAsync(file.FullName, "exclusive-held", TestContext.Current.CancellationToken);

            using FileStream exclusive = new(file.FullName, FileMode.Open, FileAccess.Read,
                FileShare.None);
            FileRecord record = BuildRecord(root.FullName, file.Name);

            var broker = new WindowsReadOnlyFileBroker(delay: (_, _) => Task.CompletedTask);
            List<FileOpenRetryEvent> events = [];

            await Assert.ThrowsAsync<WindowsSecurityException>(() =>
                broker.OpenAsync(root.FullName, record, events, TestContext.Current.CancellationToken));

            Assert.Equal(3, events.Count);
            Assert.All(events, e =>
                Assert.True(e.ErrorCode is 32 or 5,
                    $"expected sharing/access errors, got 0x{e.ErrorCode:X}"));
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Duplicate_into_worker_process_returns_positive_handle_value()
    {
        WindowsSecurityGate.AssertEnabled();
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-broker-dup-");
        try
        {
            FileInfo file = new(Path.Combine(root.FullName, "dup.txt"));
            await File.WriteAllTextAsync(file.FullName, "dup", TestContext.Current.CancellationToken);

            var broker = new WindowsReadOnlyFileBroker();
            using BrokeredReadHandle handle =
                await broker.OpenAsync(root.FullName, BuildRecord(root.FullName, file.Name),
                    TestContext.Current.CancellationToken);

            using SafeFileHandle workerProcess = FileBrokerNative.OpenCurrentProcess();
            long duplicated = await broker.DuplicateReadOnlyAsync(handle, workerProcess,
                TestContext.Current.CancellationToken);
            Assert.NotEqual(0, duplicated);
            Assert.NotEqual(-1, duplicated);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    private static FileRecord BuildRecord(string rootPath, string fileName, string? streamName = null) =>
        new(new FileId(Guid.NewGuid()), 0, fileName, null, streamName, 0, DateTimeOffset.UtcNow,
            FileAttributes.Normal,
            new FileStreamIdentity("0000000000000000", UInt128.Zero, streamName),
            [], InventoryStatus.Complete, null, null, CoverageStatus.NotCovered);
}
