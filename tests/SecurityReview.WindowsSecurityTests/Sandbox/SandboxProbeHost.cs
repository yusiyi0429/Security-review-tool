using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows.Sandbox;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

public sealed record ProbeRun(
    SandboxProbeResult? Result,
    IReadOnlyList<SessionVerdict> Verdicts,
    IReadOnlyList<MessageType> ObservedMessages,
    uint? ExitCode,
    bool WorkerExited,
    GapReason? ClassifiedGap,
    string? ProtocolError);

public sealed class ProbeLaunch : IDisposable
{
    internal ProbeLaunch(SandboxedWorkerProcess process, WorkerJob workerJob, ScanId scanId, JobId jobId)
    {
        Process = process;
        WorkerJob = workerJob;
        ScanId = scanId;
        JobId = jobId;
    }

    public SandboxedWorkerProcess Process { get; }
    public WorkerJob WorkerJob { get; }
    public ScanId ScanId { get; }
    public JobId JobId { get; }
    public string PipeName => Process.PipeName;

    public bool WorkerExited(int waitMilliseconds = 0) =>
        WorkerProcessMonitor.WaitForExit(Process.ProcessHandle, waitMilliseconds);

    public uint? WorkerExitCode() =>
        WorkerProcessMonitor.TryGetExitCode(Process.ProcessHandle, out uint code) ? code : null;

    public void TerminateWorkerJob() => WorkerJob.Terminate(1);

    // Drives the parent side of the P0-T3 session: HelloAccepted, ParseJob, then
    // validates every worker frame with the stateful session validator.
    public async Task<ProbeRun> DriveAsync(SandboxProbeHost host, TimeSpan timeout,
        bool stopAfterFirstChunk = false, CancellationToken cancellationToken = default)
    {
        var verdicts = new List<SessionVerdict>();
        var observed = new List<MessageType>();
        Stream pipe = Process.Pipe;

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        string? protocolError = null;
        try
        {
            ProtocolEnvelope helloAccepted = ProtocolEnvelope.Create(
                MessageType.HelloAccepted, Guid.NewGuid(), "{}") with
            { Sequence = 0 };
            await LengthPrefixedJsonProtocol.WriteAsync(pipe, helloAccepted, cancellationToken)
                .ConfigureAwait(false);

            var limits = new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 1, 1, 1_048_576, 65_536);
            var parseJob = new ParseJob(ProtocolConstants.Version, ScanId, JobId,
                Process.InputHandleValue, host.AllowedFileLength, "probe",
                host.ForbiddenSiblingPath, limits, [.. host.NetworkTargets]);
            string payload = JsonSerializer.Serialize(parseJob, ProtocolJsonContext.Default.ParseJob);
            ProtocolEnvelope parseJobEnvelope = ProtocolEnvelope.Create(
                MessageType.ParseJob, Guid.NewGuid(), payload, ScanId, JobId) with
            { Sequence = 1 };
            await LengthPrefixedJsonProtocol.WriteAsync(pipe, parseJobEnvelope, cancellationToken)
                .ConfigureAwait(false);

            while (true)
            {
                (ProtocolEnvelope message, byte[] rawFrame) =
                    await LengthPrefixedJsonProtocol.ReadWithRawAsync(pipe, deadline.Token)
                        .ConfigureAwait(false);
                SessionVerdict verdict = Process.Session.Validate(message, rawFrame);
                verdicts.Add(verdict);
                observed.Add(message.MessageType);
                if (verdict == SessionVerdict.TerminateJob)
                {
                    TerminateWorkerJob();
                    protocolError = "session_terminated_by_validator";
                    break;
                }

                if (stopAfterFirstChunk && message.MessageType == MessageType.ContentChunk)
                {
                    return Finish(null, verdicts, observed, null, null);
                }

                if (message.MessageType == MessageType.ParseCompleted)
                {
                    SandboxProbeResult? result = JsonSerializer.Deserialize<SandboxProbeResult>(
                        message.PayloadJson, ProbeJson.Options);
                    return Finish(result, verdicts, observed, null, null);
                }
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested)
        {
            TerminateWorkerJob();
            return Finish(null, verdicts, observed, GapReason.ParserTimeout, "deadline_exceeded");
        }
        catch (ProtocolException ex)
        {
            TerminateWorkerJob();
            protocolError = ex.Message;
        }
        catch (IOException)
        {
            // Worker closed the pipe (exit or job kill); EndOfStreamException included.
        }

        return Finish(null, verdicts, observed, null, protocolError);

        ProbeRun Finish(SandboxProbeResult? result, List<SessionVerdict> v,
            List<MessageType> o, GapReason? gap, string? error)
        {
            bool exited = WorkerExited(5_000);
            uint? exitCode = exited ? WorkerExitCode() : null;
            GapReason? classified = result is not null ? null
                : gap ?? (error is not null ? GapReason.ParserProtocolMismatch
                : exitCode == SandboxProbeHost.MemoryLimitExitCode ? GapReason.ParserMemory
                : GapReason.ParserCrash);
            return new ProbeRun(result, v, o, exitCode, exited, classified, error);
        }
    }

    public void Dispose()
    {
        Process.Dispose();
        WorkerJob.Dispose();
    }
}

public sealed class SandboxProbeHost : IDisposable
{
    public const uint MemoryLimitExitCode = 86;
    public const string WorkerExecutableName = "SecurityReview.Worker.exe";
    public const string ManifestFileName = "worker-manifest.json";
    public const string AllowedCanary = "CANARY_ALLOWED";
    public const string ForbiddenCanary = "CANARY_FORBIDDEN";

    private static readonly string[] NetworkCapabilitySids =
        ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"];

    private readonly DirectoryInfo _tempRoot;
    private readonly TcpListener _loopbackListener;
    private readonly TcpListener _lanListener;
    private readonly AppContainerWorkerLauncher _launcher = new();
    private bool _jobSetDisposed;

    private SandboxProbeHost(string stagingDirectory, string appContainerSid,
        DirectoryInfo tempRoot, TcpListener loopbackListener, TcpListener lanListener,
        IReadOnlyList<string> networkTargets)
    {
        StagingDirectory = stagingDirectory;
        ExpectedAppContainerSid = appContainerSid;
        _tempRoot = tempRoot;
        _loopbackListener = loopbackListener;
        _lanListener = lanListener;
        NetworkTargets = networkTargets;
        Jobs = WorkerJobSet.Create(ScanJobLimits.ScanDefault);
    }

    public string StagingDirectory { get; }
    public string ExpectedAppContainerSid { get; }
    public WorkerJobSet Jobs { get; }
    public IReadOnlyList<string> NetworkTargets { get; }
    public string AllowedPath { get; private set; } = string.Empty;
    public string ForbiddenSiblingPath { get; private set; } = string.Empty;
    public long AllowedFileLength { get; private set; }

    public static IReadOnlyList<string> NetworkCapabilitySidsUnderTest => NetworkCapabilitySids;

    public static async Task<SandboxProbeHost> CreateAsync()
    {
        WindowsSecurityGate.AssertEnabled();

        string staging = Environment.GetEnvironmentVariable(
            WindowsSecurityGate.ProbeWorkerDirectoryVariable)
            ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "WorkerProbe"));
        if (!File.Exists(Path.Combine(staging, ManifestFileName))
            || !File.Exists(Path.Combine(staging, WorkerExecutableName)))
        {
            Assert.Fail(
                $"Probe worker staging directory '{staging}' is incomplete. Publish the worker "
                + "with -p:SecurityReviewSandboxProbe=true and generate worker-manifest.json "
                + "(see build/windows-lane.sh).");
        }

        var launcher = new AppContainerWorkerLauncher();
        // Verifies the staged worker hashes (SHA-256) before granting the profile
        // any access to the staging directory; fails closed on mismatch.
        AppContainerProfileInfo profile = await launcher
            .PrepareAsync(staging, WorkerExecutableName, CancellationToken.None)
            .ConfigureAwait(false);

        DirectoryInfo tempRoot = Directory.CreateTempSubdirectory("srt-probe-");
        string allowed = Path.Combine(tempRoot.FullName, "allowed.txt");
        string forbidden = Path.Combine(tempRoot.FullName, "forbidden.txt");
        await File.WriteAllTextAsync(allowed, AllowedCanary).ConfigureAwait(false);
        await File.WriteAllTextAsync(forbidden, ForbiddenCanary).ConfigureAwait(false);

        var loopback = new TcpListener(IPAddress.Loopback, 0);
        loopback.Start();
        IPAddress lanAddress = Dns.GetHostAddresses(Dns.GetHostName())
            .First(a => a.AddressFamily == AddressFamily.InterNetwork);
        var lan = new TcpListener(lanAddress, 0);
        lan.Start();

        var targets = new List<string>
        {
            $"tcp:127.0.0.1:{((IPEndPoint)loopback.LocalEndpoint).Port}",
            $"tcp:{lanAddress}:{((IPEndPoint)lan.LocalEndpoint).Port}",
            "udp:8.8.8.8:53",
            "dns:example.com",
            "tcp:192.0.2.1:443",
        };

        return new SandboxProbeHost(staging, profile.SidString, tempRoot, loopback, lan, targets)
        {
            AllowedPath = allowed,
            ForbiddenSiblingPath = forbidden,
            AllowedFileLength = new FileInfo(allowed).Length,
        };
    }

    public async Task<ProbeLaunch> LaunchAsync(ProbeScenario scenario,
        WorkerJobLimits? limits = null, string? additionalWorkerArguments = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_jobSetDisposed, this);
        var scanId = new ScanId(Guid.NewGuid());
        var jobId = new JobId(Guid.NewGuid());
        WorkerJob workerJob = Jobs.CreateWorkerJob(limits ?? WorkerJobLimits.OrdinaryWorker);
        try
        {
            string args = $"--probe {scenario}";
            if (additionalWorkerArguments is not null)
            {
                args += " " + additionalWorkerArguments;
            }

            var request = new WorkerLaunchRequest(scanId, jobId, StagingDirectory,
                WorkerExecutableName, AllowedPath, Jobs.ScanJob, workerJob, args);
            SandboxedWorkerProcess process = await _launcher
                .LaunchAsync(request, cancellationToken).ConfigureAwait(false);
            return new ProbeLaunch(process, workerJob, scanId, jobId);
        }
        catch
        {
            workerJob.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        _jobSetDisposed = true;
        Jobs.Dispose();
        _loopbackListener.Stop();
        _lanListener.Stop();
        try
        {
            _tempRoot.Delete(recursive: true);
        }
        catch (IOException)
        {
            // Temp cleanup is best-effort on Windows.
        }
        catch (UnauthorizedAccessException)
        {
            // Temp cleanup is best-effort on Windows.
        }
    }
}

internal static class ProbeJson
{
    public static readonly JsonSerializerOptions Options =
        new(JsonSerializerDefaults.Web) { PropertyNameCaseInsensitive = true };
}
