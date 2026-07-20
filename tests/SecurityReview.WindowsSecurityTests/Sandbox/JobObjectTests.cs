using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Sandbox;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

public sealed class JobObjectTests
{
    [Fact]
    public async Task per_worker_job_blocks_child_spawn_and_scan_job_allows_worker_pool()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();

        // Scan-wide job permits the configured pool of four active workers.
        var pool = new List<ProbeLaunch>();
        try
        {
            for (int i = 0; i < ScanJobLimits.ScanDefault.ActiveProcessLimit; i++)
            {
                pool.Add(await host.LaunchAsync(ProbeScenario.HangPastDeadline,
                    cancellationToken: ct));
            }

            Assert.All(pool, launch => Assert.False(launch.WorkerExited()));

            // A fifth process does not fit the scan-wide active-process limit:
            // assignment fails closed instead of falling back to an unsandboxed worker.
            await Assert.ThrowsAsync<WindowsSecurityException>(() =>
                host.LaunchAsync(ProbeScenario.TokenInspection, cancellationToken: ct));
        }
        finally
        {
            foreach (ProbeLaunch launch in pool)
            {
                launch.Dispose();
            }
        }

        // Per-worker child job (active-process limit 1) denies the worker a child.
        using ProbeLaunch spawner = await host.LaunchAsync(ProbeScenario.SpawnChild,
            cancellationToken: ct);
        ProbeRun spawnRun = await spawner.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);
        Assert.NotNull(spawnRun.Result);
        Assert.Equal(ProbeAccess.Denied, spawnRun.Result.ChildSpawn);
    }

    [Fact]
    public async Task ordinary_worker_512mib_allocation_terminates_and_reports_parser_memory()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.Allocate512MiB,
            WorkerJobLimits.OrdinaryWorker, cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(60),
            cancellationToken: ct);

        Assert.Null(run.Result);
        Assert.True(run.WorkerExited);
        Assert.Equal(GapReason.ParserMemory, run.ClassifiedGap);
    }

    [Fact]
    public async Task oci_exclusive_worker_holds_512mib_under_the_1gib_ceiling()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.Allocate512MiB,
            WorkerJobLimits.OciExclusiveWorker, cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(60),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.Equal(512, run.Result.AllocatedMebiBytes);
        Assert.Null(run.ClassifiedGap);
    }

    [Fact]
    public async Task hanging_worker_is_terminated_at_deadline_and_reports_parser_timeout()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.HangPastDeadline,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(2),
            cancellationToken: ct);

        Assert.Null(run.Result);
        Assert.Equal(GapReason.ParserTimeout, run.ClassifiedGap);
        Assert.True(launch.WorkerExited(5_000), "Deadline kill must reap the worker.");
    }

    [Fact]
    public async Task closing_worker_job_kills_only_its_worker_closing_scan_job_kills_all()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch first = await host.LaunchAsync(ProbeScenario.HangPastDeadline,
            cancellationToken: ct);
        using ProbeLaunch second = await host.LaunchAsync(ProbeScenario.HangPastDeadline,
            cancellationToken: ct);

        Task<ProbeRun> firstDrive = first.DriveAsync(host, TimeSpan.FromSeconds(60),
            cancellationToken: ct);
        Task<ProbeRun> secondDrive = second.DriveAsync(host, TimeSpan.FromSeconds(60),
            cancellationToken: ct);

        first.WorkerJob.Dispose();
        Assert.True(first.WorkerExited(5_000), "Closing the child job must kill its worker.");
        Assert.False(second.WorkerExited(), "Closing a sibling child job must not kill this worker.");

        host.Jobs.Dispose();
        Assert.True(second.WorkerExited(5_000), "Closing the scan job must kill remaining workers.");

        await firstDrive;
        await secondDrive;
    }
}
