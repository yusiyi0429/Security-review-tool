using System.IO.Pipes;
using System.Security.Principal;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows.Sandbox;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

public sealed class PipeAndHandleTests
{
    private static readonly string[] ForbiddenSids =
    [
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // Authenticated Users
        "S-1-5-32-545", // Users
        "S-1-15-2-1",   // All Application Packages
        "S-1-15-2-2",   // All Restricted Application Packages
    ];

    [Fact]
    public async Task second_pipe_client_is_rejected()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.HangPastDeadline,
            cancellationToken: ct);

        using var secondClient = new NamedPipeClientStream(".", launch.PipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);
        Exception? error = await Record.ExceptionAsync(() => secondClient.ConnectAsync(2_000, ct));
        Assert.NotNull(error);

        launch.TerminateWorkerJob();
        Assert.True(launch.WorkerExited(5_000));
    }

    [Fact]
    public async Task pipe_sddl_grants_only_current_user_and_appcontainer_sid()
    {
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();

        using NamedPipeServerStream pipe = RestrictedPipeFactory.CreateServerPipe(
            host.ExpectedAppContainerSid, out _, out string appliedSddl);

        string userSid = WindowsIdentity.GetCurrent().User!.Value;
        Assert.Contains(userSid, appliedSddl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(host.ExpectedAppContainerSid, appliedSddl, StringComparison.OrdinalIgnoreCase);
        foreach (string forbidden in ForbiddenSids)
        {
            Assert.DoesNotContain(forbidden, appliedSddl, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Theory]
    [InlineData(ProbeScenario.ProtocolWrongNonce)]
    [InlineData(ProbeScenario.ProtocolWrongBuild)]
    public async Task handshake_spoof_terminates_launch(ProbeScenario scenario)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();

        await Assert.ThrowsAsync<ProtocolException>(() =>
            host.LaunchAsync(scenario, cancellationToken: ct));
    }

    [Theory]
    [InlineData(ProbeScenario.ProtocolSkipSequence)]
    [InlineData(ProbeScenario.ProtocolConflictingDuplicate)]
    [InlineData(ProbeScenario.ProtocolOversizedFrame)]
    public async Task protocol_violation_terminates_session_and_job(ProbeScenario scenario)
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(scenario, cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);

        Assert.Null(run.Result);
        Assert.Equal(GapReason.ParserProtocolMismatch, run.ClassifiedGap);
        if (scenario == ProbeScenario.ProtocolOversizedFrame)
        {
            Assert.NotNull(run.ProtocolError);
        }
        else
        {
            Assert.Contains(SessionVerdict.TerminateJob, run.Verdicts);
        }

        Assert.True(launch.WorkerExited(5_000), "Violating worker must be terminated.");
    }

    [Fact]
    public async Task exact_retransmission_is_ignored_idempotently()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.ProtocolExactRetransmit,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.Equal(
            [SessionVerdict.Accept, SessionVerdict.IgnoreDuplicate, SessionVerdict.Accept],
            run.Verdicts);
    }

    [Fact]
    public async Task duplicated_handle_is_read_only()
    {
        CancellationToken ct = TestContext.Current.CancellationToken;
        using SandboxProbeHost host = await SandboxProbeHost.CreateAsync();
        using ProbeLaunch launch = await host.LaunchAsync(ProbeScenario.HandleAndSiblingRead,
            cancellationToken: ct);

        ProbeRun run = await launch.DriveAsync(host, TimeSpan.FromSeconds(30),
            cancellationToken: ct);

        Assert.NotNull(run.Result);
        Assert.Equal(SandboxProbeHost.AllowedCanary, run.Result.HandleText);
        Assert.Equal(ProbeAccess.Denied, run.Result.HandleWrite);
    }
}
