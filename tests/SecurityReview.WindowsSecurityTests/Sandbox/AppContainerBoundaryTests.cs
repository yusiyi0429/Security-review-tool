using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Sandbox;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

public sealed class AppContainerBoundaryTests
{
    [Fact]
    public async Task worker_reads_duplicated_handle_but_not_sibling_path()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.HandleAndSiblingRead,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.Equal(SandboxProbeHost.AllowedCanary, run.Result.HandleText);
        Assert.Equal(ProbeAccess.Denied, run.Result.SiblingRead);
        Assert.Null(run.ClassifiedGap);
    }

    [Fact]
    public async Task worker_cannot_connect_to_loopback_lan_dns_or_internet()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.NetworkMatrix,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(60),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.Equal(host.NetworkTargets.Count, run.Result.NetworkAttempts.Count);
        Assert.All(run.Result.NetworkAttempts,
            attempt => Assert.Equal(ProbeAccess.Denied, attempt.Access));
    }

    [Fact]
    public async Task worker_token_contains_expected_appcontainer_sid_and_no_network_capability()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.TokenInspection,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.True(run.Result.IsAppContainer);
        Assert.Equal(host.ExpectedAppContainerSid, run.Result.AppContainerSid);
        Assert.Empty(run.Result.TokenCapabilities);
        Assert.DoesNotContain(run.Result.TokenCapabilities, sid =>
            SandboxProbeHost.NetworkCapabilitySidsUnderTest.Contains(sid,
                StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task worker_cannot_use_handle_after_parent_disposes_job()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.HandleReuseAfterDispose,
            cancellationToken: ct);

        ProbeRun firstChunk = await launch.DriveAsync(host, TimeSpan.FromSeconds(15),
            stopAfterFirstChunk: true, cancellationToken: ct);
        Assert.Contains(MessageType.ContentChunk, firstChunk.ObservedMessages);
        Assert.False(launch.WorkerExited());

        launch.TerminateWorkerJob();

        Assert.True(launch.WorkerExited(5_000), "Worker must die with its job.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        Exception? error = await Record.ExceptionAsync(() =>
            LengthPrefixedJsonProtocol.ReadWithRawAsync(launch.Process.Pipe, timeout.Token));
        Assert.True(error is IOException or EndOfStreamException or OperationCanceledException,
            $"No post-kill frame may arrive; got {(error is null ? "a frame" : error.GetType().Name)}.");
    }

    [Fact]
    public async Task parent_process_remains_alive_after_worker_crash()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        uint crashExitCode;
        using (ProbeLaunch crashed = await host.LaunchAsync(ProbeScenario.CrashNonZero,
            cancellationToken: ct))
        {
            ProbeRun crashRun = await crashed.DriveAsync(host, TimeSpan.FromSeconds(30),
                cancellationToken: ct);
            Assert.True(crashRun.WorkerExited);
            Assert.NotNull(crashRun.ExitCode);
            Assert.NotEqual(0u, crashRun.ExitCode.Value);
            Assert.Equal(Domain.Scans.GapReason.ParserCrash, crashRun.ClassifiedGap);
            crashExitCode = crashRun.ExitCode.Value;
        }

        // The parent side is unharmed: a fresh worker still launches and answers.
        using ProbeLaunch survivor = await host.LaunchAsync(ProbeScenario.TokenInspection,
            cancellationToken: ct);
        ProbeRun survivorRun = await survivor.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);
        Assert.NotNull(survivorRun.Result);
        Assert.True(survivorRun.Result.IsAppContainer);
        Assert.Equal(3u, crashExitCode);
    }

    [Fact]
    public async Task tampered_worker_manifest_fails_closed()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        DirectoryInfo fake = Directory.CreateTempSubdirectory("srt-fake-worker-");
        try
        {
            string exePath = Path.Combine(fake.FullName, SandboxProbeHost.WorkerExecutableName);
            await File.WriteAllBytesAsync(exePath, [1, 2, 3, 4], ct);
            string wrongHash = new string('0', 64);
            await File.WriteAllTextAsync(Path.Combine(fake.FullName,
                SandboxProbeHost.ManifestFileName),
                $"{{\"algorithm\":\"SHA256\",\"files\":{{\"{SandboxProbeHost.WorkerExecutableName}\":\"{wrongHash}\"}}}}",
                ct);

            var launcher = new AppContainerWorkerLauncher();
            await Assert.ThrowsAsync<WindowsSecurityException>(() =>
                launcher.PrepareAsync(fake.FullName, SandboxProbeHost.WorkerExecutableName, ct));
        }
        finally
        {
            fake.Delete(recursive: true);
        }
    }
}
