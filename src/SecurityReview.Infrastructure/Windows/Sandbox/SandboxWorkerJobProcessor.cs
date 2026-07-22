using System.Runtime.CompilerServices;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

/// <summary>
/// Runs one scan work item in a manifest-verified AppContainer worker. Every
/// input is passed as a duplicated read-only handle; the worker never receives
/// filesystem access to the scan root and no in-process fallback is used.
/// </summary>
public sealed class SandboxWorkerJobProcessor : IWorkerJobProcessor
{
    private readonly IWorkerLauncher _launcher;
    private readonly string _workerStagingDirectory;
    private readonly string _workerExecutableName;

    public SandboxWorkerJobProcessor(
        IWorkerLauncher launcher,
        string workerStagingDirectory,
        string workerExecutableName)
    {
        _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
        ArgumentException.ThrowIfNullOrWhiteSpace(workerStagingDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExecutableName);
        _workerStagingDirectory = workerStagingDirectory;
        _workerExecutableName = workerExecutableName;
    }

    public async IAsyncEnumerable<WorkerJobResult> ProcessAsync(
        ScanWorkItem item,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var results = new List<WorkerJobResult>();
        try
        {
            await ProcessCoreAsync(item, results, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            WorkerFailure failure = cancellationToken.IsCancellationRequested
                ? WorkerFailure.Cancelled
                : WorkerFailure.Timeout;
            results.Add(Failed(item, failure));
        }
        catch (ProtocolException)
        {
            results.Add(Failed(item, WorkerFailure.ProtocolViolation));
        }
        catch (JsonException)
        {
            results.Add(Failed(item, WorkerFailure.ProtocolViolation));
        }
        catch (Exception)
        {
            results.Add(Failed(item, WorkerFailure.Crash));
        }

        foreach (WorkerJobResult result in results)
            yield return result;
    }

    private async Task ProcessCoreAsync(
        ScanWorkItem item,
        List<WorkerJobResult> results,
        CancellationToken cancellationToken)
    {
        string? inputPath = item.InputFilePath;
        if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), item.ScanId, item.FileId, item.VirtualPath,
                item.FormatHint, "inventory", GapReason.AccessDenied,
                "file_not_found", item.DeclaredLength, 0, DateTimeOffset.UtcNow);
            results.Add(new WorkerJobResult(item.JobId, item.FileId,
                WorkerResultKind.Failed, null, gap, null, null, null));
            return;
        }

        using WorkerJobSet jobs = WorkerJobSet.Create(ScanJobLimits.ScanDefault);
        WorkerJob workerJob = jobs.CreateWorkerJob(item.IsOci
            ? WorkerJobLimits.OciExclusiveWorker
            : WorkerJobLimits.OrdinaryWorker);

        var request = new WorkerLaunchRequest(
            item.ScanId,
            item.JobId,
            _workerStagingDirectory,
            _workerExecutableName,
            inputPath,
            jobs.ScanJob,
            workerJob,
            AdditionalWorkerArguments: null);

        using SandboxedWorkerProcess process = await _launcher
            .LaunchAsync(request, cancellationToken).ConfigureAwait(false);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        TimeSpan remaining = item.Limits.DeadlineUtc - DateTimeOffset.UtcNow;
        deadline.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);

        try
        {
            await SendHostMessagesAsync(process, item, deadline.Token).ConfigureAwait(false);
            await ReadWorkerMessagesAsync(process, item, results, deadline.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await TrySendCancelAsync(process, item).ConfigureAwait(false);
            process.TerminateWorker();
            throw;
        }
    }

    private static async Task SendHostMessagesAsync(
        SandboxedWorkerProcess process,
        ScanWorkItem item,
        CancellationToken cancellationToken)
    {
        ProtocolEnvelope helloAccepted = ProtocolEnvelope.Create(
            MessageType.HelloAccepted, Guid.NewGuid(), "{}") with
        { Sequence = 0 };
        await LengthPrefixedJsonProtocol.WriteAsync(
            process.Pipe, helloAccepted, cancellationToken).ConfigureAwait(false);

        var parseJob = new ParseJob(
            ProtocolConstants.Version,
            item.ScanId,
            item.JobId,
            process.InputHandleValue,
            item.DeclaredLength,
            item.FormatHint,
            item.VirtualPath,
            item.Limits,
            Array.Empty<string>());
        string payload = JsonSerializer.Serialize(
            parseJob, ProtocolJsonContext.Default.ParseJob);
        ProtocolEnvelope envelope = ProtocolEnvelope.Create(
            MessageType.ParseJob, Guid.NewGuid(), payload, item.ScanId, item.JobId) with
        { Sequence = 1 };
        await LengthPrefixedJsonProtocol.WriteAsync(
            process.Pipe, envelope, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ReadWorkerMessagesAsync(
        SandboxedWorkerProcess process,
        ScanWorkItem item,
        List<WorkerJobResult> results,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            (ProtocolEnvelope envelope, byte[] rawFrame) = await LengthPrefixedJsonProtocol
                .ReadWithRawAsync(process.Pipe, cancellationToken).ConfigureAwait(false);
            SessionVerdict verdict = process.Session.Validate(envelope, rawFrame);
            if (verdict == SessionVerdict.IgnoreDuplicate)
                continue;
            if (verdict == SessionVerdict.TerminateJob)
                throw new ProtocolException("Worker protocol validation failed.");

            switch (envelope.MessageType)
            {
                case MessageType.ContentChunk:
                    ContentChunk? chunk = JsonSerializer.Deserialize(
                        envelope.PayloadJson, ProtocolJsonContext.Default.ContentChunk);
                    if (chunk is null || chunk.JobId != item.JobId
                        || chunk.Validate(item.DeclaredLength).Count != 0)
                    {
                        throw new ProtocolException("Worker returned an invalid content chunk.");
                    }
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Chunk, chunk, null, null, null, null));
                    break;

                case MessageType.GapProduced:
                    WorkerGapPayload? gapPayload = JsonSerializer.Deserialize(
                        envelope.PayloadJson, ProtocolJsonContext.Default.WorkerGapPayload);
                    if (gapPayload is null || !Enum.TryParse(
                        gapPayload.Reason, ignoreCase: false, out GapReason reason))
                    {
                        throw new ProtocolException("Worker returned an invalid coverage gap.");
                    }
                    var gap = new CoverageGap(
                        Guid.NewGuid(), item.ScanId, item.FileId,
                        gapPayload.VirtualPath ?? item.VirtualPath,
                        gapPayload.FormatId ?? item.FormatHint,
                        "parse", reason, gapPayload.DetailCode,
                        gapPayload.PlannedBytes ?? item.DeclaredLength,
                        gapPayload.ProcessedBytes,
                        DateTimeOffset.UtcNow);
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Gap, null, gap, null, null, null));
                    break;

                case MessageType.ChildDiscovered:
                    WorkerChildPayload? child = JsonSerializer.Deserialize(
                        envelope.PayloadJson, ProtocolJsonContext.Default.WorkerChildPayload);
                    if (child is null)
                        throw new ProtocolException("Worker returned invalid child metadata.");
                    var detected = DetectedFormat.Create(child.FormatId, child.Confidence,
                        ["sandbox-worker"], mismatch: false);
                    var probe = new FormatProbe(ReadOnlyMemory<byte>.Empty,
                        ReadOnlyMemory<byte>.Empty, null, child.DeclaredLength, detected);
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.ChildDiscovered, null, null,
                        child.VirtualPath, probe, null));
                    break;

                case MessageType.ParseCompleted:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Completed, null, null, null, null, null));
                    return;

                case MessageType.ParseFailed:
                    WorkerFailurePayload? failure = JsonSerializer.Deserialize(
                        envelope.PayloadJson, ProtocolJsonContext.Default.WorkerFailurePayload);
                    WorkerFailure mapped = failure?.ErrorCode switch
                    {
                        "cancelled" => WorkerFailure.Cancelled,
                        "timeout" => WorkerFailure.Timeout,
                        "invalid_parse_job" => WorkerFailure.ProtocolViolation,
                        _ => WorkerFailure.Crash,
                    };
                    results.Add(Failed(item, mapped));
                    return;

                case MessageType.Heartbeat:
                    break;

                default:
                    throw new ProtocolException("Worker returned an unexpected message.");
            }
        }
    }

    private static async Task TrySendCancelAsync(
        SandboxedWorkerProcess process,
        ScanWorkItem item)
    {
        try
        {
            ProtocolEnvelope cancel = ProtocolEnvelope.Create(
                MessageType.CancelJob, Guid.NewGuid(), "{}", item.ScanId, item.JobId) with
            { Sequence = 2 };
            await LengthPrefixedJsonProtocol.WriteAsync(
                process.Pipe, cancel, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Termination of the per-worker job remains the fail-closed fallback.
        }
    }

    private static WorkerJobResult Failed(ScanWorkItem item, WorkerFailure failure)
    {
        GapReason reason = WorkerFailureMapper.MapFailure(failure);
        var gap = new CoverageGap(
            Guid.NewGuid(), item.ScanId, item.FileId, item.VirtualPath,
            item.FormatHint, "parse", reason,
            failure.ToString(), item.DeclaredLength, 0, DateTimeOffset.UtcNow);

        return new WorkerJobResult(
            item.JobId,
            item.FileId,
            failure == WorkerFailure.Cancelled
                ? WorkerResultKind.Cancelled
                : WorkerResultKind.Failed,
            null,
            gap,
            null,
            null,
            failure);
    }
}
