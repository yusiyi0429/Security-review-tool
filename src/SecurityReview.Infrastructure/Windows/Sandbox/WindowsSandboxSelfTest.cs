using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

public sealed record SandboxSelfTestEnvironment(string WorkerStagingDirectory,
    string WorkerExecutableName);

// Verified-preparation surface of the worker launcher: manifest verification
// before any ACL grant, plus the verified worker build hash for fingerprinting.
public interface IWorkerLaunchPreparer
{
    Task<AppContainerProfileInfo> PrepareAsync(string workerStagingDirectory,
        string workerExecutableName, CancellationToken cancellationToken);

    Task<string> GetVerifiedWorkerBuildHashAsync(string workerStagingDirectory,
        string workerExecutableName, CancellationToken cancellationToken);
}

// Bounded, fingerprint-bound sandbox self-test. Proves per run: AppContainer
// token identity with zero capabilities, no loopback connection, read-only
// duplicated handle, sibling path denied, and Job kill-on-close. A success is
// cached at most 24 hours and only while worker SHA-256, OS build,
// AppContainer SID, executable manifest, and policy fingerprint all match.
// Fail-closed: failures are never cached and there is no fallback launcher.
public sealed class WindowsSandboxSelfTest : ISandboxSelfTest
{
    private const string ManifestFileName = "worker-manifest.json";
    private const string AllowedCanary = "CANARY_ALLOWED";
    private const string DeniedMarker = "Denied";

    private static readonly JsonSerializerOptions ProbeJsonOptions =
        new(JsonSerializerDefaults.Web) { PropertyNameCaseInsensitive = true };

    private readonly IWorkerLauncher _launcher;
    private readonly IWorkerLaunchPreparer _preparer;
    private readonly SandboxSelfTestEnvironment _environment;
    private readonly ISandboxSelfTestCache _cache;

    public WindowsSandboxSelfTest(IWorkerLauncher launcher, IWorkerLaunchPreparer preparer,
        SandboxSelfTestEnvironment environment, ISandboxSelfTestCache? cache = null)
    {
        _launcher = launcher;
        _preparer = preparer;
        _environment = environment;
        _cache = cache ?? new InMemorySandboxSelfTestCache();
    }

    public async Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken)
    {
        string manifestPath = Path.Combine(_environment.WorkerStagingDirectory,
            ManifestFileName);
        if (!File.Exists(manifestPath))
        {
            return SandboxSelfTestResult.Failed("worker_manifest_missing");
        }

        try
        {
            string manifestSha256 = Convert.ToHexString(
                SHA256.HashData(await File.ReadAllBytesAsync(manifestPath, cancellationToken)
                    .ConfigureAwait(false))).ToLowerInvariant();
            // PrepareAsync verifies the manifest before any ACL grant.
            AppContainerProfileInfo profile = await _preparer.PrepareAsync(
                _environment.WorkerStagingDirectory, _environment.WorkerExecutableName,
                cancellationToken).ConfigureAwait(false);
            string workerSha256 = await _preparer.GetVerifiedWorkerBuildHashAsync(
                _environment.WorkerStagingDirectory, _environment.WorkerExecutableName,
                cancellationToken).ConfigureAwait(false);
            string osBuild = Environment.OSVersion.Version.Build.ToString(
                System.Globalization.CultureInfo.InvariantCulture);

            var fingerprint = new SandboxSelfTestFingerprint(workerSha256, osBuild,
                profile.SidString, manifestSha256, PolicyFingerprint());
            DateTimeOffset now = DateTimeOffset.UtcNow;
            SandboxSelfTestResult? cached = _cache.Read(fingerprint, now);
            if (cached is not null)
            {
                return cached;
            }

            string checkCode = await RunChecksAsync(profile.SidString, cancellationToken)
                .ConfigureAwait(false);
            if (checkCode != SandboxSelfTestResult.OkCode)
            {
                return SandboxSelfTestResult.Failed(checkCode);
            }

            var passed = new SandboxSelfTestResult(true, SandboxSelfTestResult.OkCode,
                workerSha256, osBuild, profile.SidString, DateTimeOffset.UtcNow);
            _cache.Write(fingerprint, passed);
            return passed;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WindowsSecurityException)
        {
            return SandboxSelfTestResult.Failed("sandbox_profile_unavailable");
        }
        catch (ProtocolException)
        {
            return SandboxSelfTestResult.Failed("worker_launch_failed");
        }
        catch (IOException)
        {
            return SandboxSelfTestResult.Failed("worker_launch_failed");
        }
    }

    // Canonical fingerprint of the enforced sandbox policy: any change to the
    // profile, job limits, pipe policy, or protocol invalidates cached success.
    internal static string PolicyFingerprint()
    {
        ScanJobLimits scan = ScanJobLimits.ScanDefault;
        WorkerJobLimits ordinary = WorkerJobLimits.OrdinaryWorker;
        WorkerJobLimits oci = WorkerJobLimits.OciExclusiveWorker;
        string canonical = string.Join('|',
            $"profile={AppContainerProfile.ProfileName}",
            $"scan={scan.ActiveProcessLimit}/{scan.JobMemoryBytes}/{scan.KillOnJobClose}",
            $"worker={ordinary.ActiveProcessLimit}/{ordinary.ProcessMemoryBytes}/{ordinary.DieOnUnhandledException}",
            $"oci={oci.ProcessMemoryBytes}",
            $"pipe={RestrictedPipeFactory.PipeBufferBytes}",
            $"proto={ProtocolConstants.Version}",
            "manifest=sha256");
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
    }

    private async Task<string> RunChecksAsync(string expectedSid,
        CancellationToken cancellationToken)
    {
        DirectoryInfo workspace = Directory.CreateTempSubdirectory("srt-selftest-");
        TcpListener? loopback = null;
        try
        {
            string allowedPath = Path.Combine(workspace.FullName, "allowed.txt");
            string forbiddenPath = Path.Combine(workspace.FullName, "forbidden.txt");
            await File.WriteAllTextAsync(allowedPath, AllowedCanary, cancellationToken)
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(forbiddenPath, "CANARY_FORBIDDEN", cancellationToken)
                .ConfigureAwait(false);
            loopback = new TcpListener(IPAddress.Loopback, 0);
            loopback.Start();
            string loopbackTarget =
                $"tcp:127.0.0.1:{((System.Net.IPEndPoint)loopback.LocalEndpoint).Port}";

            using WorkerJobSet jobs = WorkerJobSet.Create(ScanJobLimits.ScanDefault);

            ProbeResult token = await RunProbeAsync(jobs, "TokenInspection", allowedPath,
                forbiddenPath, [], cancellationToken).ConfigureAwait(false);
            if (token.IsAppContainer != true)
            {
                return "appcontainer_token_missing";
            }

            if (!string.Equals(token.AppContainerSid, expectedSid,
                StringComparison.OrdinalIgnoreCase))
            {
                return "appcontainer_sid_mismatch";
            }

            if (token.TokenCapabilities is not { Count: 0 })
            {
                return "capabilities_not_empty";
            }

            WorkerJob handleJob;
            SandboxedWorkerProcess handleProcess;
            ProbeResult handle;
            (handleProcess, handleJob, handle) = await RunProbeAsync(jobs,
                "HandleAndSiblingRead", allowedPath, forbiddenPath, [],
                keepAlive: true, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            try
            {
                if (!string.Equals(handle.HandleText?.Trim(), AllowedCanary,
                    StringComparison.Ordinal))
                {
                    return "handle_read_failed";
                }

                if (handle.SiblingRead != DeniedMarker)
                {
                    return "sibling_read_not_denied";
                }

                if (handle.HandleWrite != DeniedMarker)
                {
                    return "handle_write_not_denied";
                }

                // Closing the per-worker Job handle must reap the worker via
                // the kill-on-close flag.
                handleJob.Dispose();
                if (!WorkerProcessMonitor.WaitForExit(handleProcess.ProcessHandle, 5_000))
                {
                    return "job_kill_failed";
                }
            }
            finally
            {
                handleJob.Dispose();
                handleProcess.Dispose();
            }

            ProbeResult network = await RunProbeAsync(jobs, "NetworkMatrix", allowedPath,
                forbiddenPath, [loopbackTarget], cancellationToken).ConfigureAwait(false);
            if (network.NetworkAttempts is not [{ Access: DeniedMarker }])
            {
                return "network_denial_failed";
            }

            return SandboxSelfTestResult.OkCode;
        }
        finally
        {
            loopback?.Stop();
            try
            {
                workspace.Delete(recursive: true);
            }
            catch (IOException)
            {
                // Temp cleanup is best-effort.
            }
            catch (UnauthorizedAccessException)
            {
                // Temp cleanup is best-effort.
            }
        }
    }

    private async Task<ProbeResult> RunProbeAsync(WorkerJobSet jobs, string scenario,
        string allowedPath, string forbiddenPath, IReadOnlyList<string> targets,
        CancellationToken cancellationToken) =>
        (await RunProbeAsync(jobs, scenario, allowedPath, forbiddenPath, targets,
            keepAlive: false, cancellationToken).ConfigureAwait(false)).Result;

    private async Task<(SandboxedWorkerProcess Process, WorkerJob Job, ProbeResult Result)>
        RunProbeAsync(WorkerJobSet jobs, string scenario, string allowedPath,
            string forbiddenPath, IReadOnlyList<string> targets, bool keepAlive,
            CancellationToken cancellationToken)
    {
        var scanId = new Domain.ScanId(Guid.NewGuid());
        var jobId = new Domain.JobId(Guid.NewGuid());
        WorkerJob workerJob = jobs.CreateWorkerJob(WorkerJobLimits.OrdinaryWorker);
        SandboxedWorkerProcess? process = null;
        try
        {
            var request = new WorkerLaunchRequest(scanId, jobId,
                _environment.WorkerStagingDirectory, _environment.WorkerExecutableName,
                allowedPath, jobs.ScanJob, workerJob, $"--probe {scenario}");
            process = await _launcher.LaunchAsync(request, cancellationToken)
                .ConfigureAwait(false);

            Stream pipe = process.Pipe;
            ProtocolEnvelope helloAccepted = ProtocolEnvelope.Create(
                MessageType.HelloAccepted, Guid.NewGuid(), "{}") with
            { Sequence = 0 };
            await LengthPrefixedJsonProtocol.WriteAsync(pipe, helloAccepted, cancellationToken)
                .ConfigureAwait(false);

            var limits = new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(2), 1, 1,
                1_048_576, 65_536);
            var parseJob = new ParseJob(ProtocolConstants.Version, scanId, jobId,
                process.InputHandleValue, new FileInfo(allowedPath).Length, "probe",
                forbiddenPath, limits, targets);
            string payload = JsonSerializer.Serialize(parseJob,
                ProtocolJsonContext.Default.ParseJob);
            ProtocolEnvelope parseJobEnvelope = ProtocolEnvelope.Create(
                MessageType.ParseJob, Guid.NewGuid(), payload, scanId, jobId)
                with
            { Sequence = 1 };
            await LengthPrefixedJsonProtocol.WriteAsync(pipe, parseJobEnvelope,
                cancellationToken).ConfigureAwait(false);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            while (true)
            {
                (ProtocolEnvelope message, byte[] rawFrame) = await LengthPrefixedJsonProtocol
                    .ReadWithRawAsync(pipe, timeout.Token).ConfigureAwait(false);
                SessionVerdict verdict = process.Session.Validate(message, rawFrame);
                if (verdict == SessionVerdict.TerminateJob)
                {
                    throw new ProtocolException("Self-test worker violated the protocol.");
                }

                if (verdict == SessionVerdict.IgnoreDuplicate)
                {
                    continue;
                }

                if (message.MessageType == MessageType.ParseCompleted)
                {
                    ProbeResult? result = JsonSerializer.Deserialize<ProbeResult>(
                        message.PayloadJson, ProbeJsonOptions);
                    if (result is null)
                    {
                        throw new ProtocolException("Self-test worker returned no result.");
                    }

                    if (!keepAlive)
                    {
                        process.TerminateWorker();
                        process.Dispose();
                        workerJob.Dispose();
                        return (null!, null!, result);
                    }

                    return (process, workerJob, result);
                }
            }
        }
        catch
        {
            process?.Dispose();
            workerJob.Dispose();
            throw;
        }
    }

    // Minimal mirror of the probe worker's bounded result JSON (camelCase);
    // only the fields the self-test checks are modeled, access values compare
    // as strings against the probe's fixed labels.
    private sealed record ProbeResult(string? Scenario, string? HandleText,
        string? SiblingRead, string? HandleWrite,
        IReadOnlyList<ProbeNetworkAttemptResult>? NetworkAttempts,
        bool? IsAppContainer, string? AppContainerSid,
        IReadOnlyList<string>? TokenCapabilities, string? ChildSpawn,
        int? AllocatedMebiBytes, bool? GroupEnumerationProven, string? Note);

    private sealed record ProbeNetworkAttemptResult(string? Target, string? Access,
        string? ErrorKind);
}
