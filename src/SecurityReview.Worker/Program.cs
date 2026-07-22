using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Worker;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        WorkerArguments arguments;
        try
        {
            arguments = WorkerArguments.Parse(args);
        }
        catch (ArgumentException)
        {
            return 2;
        }

        try
        {
            using var pipe = new NamedPipeClientStream(".", arguments.PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await pipe.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);

            var context = new WorkerSessionContext(pipe, arguments.ScanId, arguments.JobId);
            byte[] helloNonce = arguments.Nonce;
            string helloBuild = arguments.BuildSha256;
#if SECURITY_REVIEW_SANDBOX_PROBE
            (helloNonce, helloBuild) = Probe.ProbeRunner.ApplyHandshakeSpoof(
                arguments.ProbeScenario, helloNonce, helloBuild);
#endif
            await context.SendHelloAsync(helloNonce, helloBuild)
                .ConfigureAwait(false);
            ProtocolEnvelope helloAccepted = await context.ReadAsync().ConfigureAwait(false);
            if (helloAccepted.MessageType != MessageType.HelloAccepted)
            {
                return 4;
            }

#if SECURITY_REVIEW_SANDBOX_PROBE
            if (arguments.ProbeScenario is not null)
            {
                return await Probe.ProbeRunner.RunAsync(arguments.ProbeScenario, context)
                    .ConfigureAwait(false);
            }
#endif
            return await RunProductionLoopAsync(context).ConfigureAwait(false);
        }
        catch (IOException)
        {
            return 1;
        }
        catch (ProtocolException)
        {
            return 4;
        }
        catch (OperationCanceledException)
        {
            return 1;
        }
        catch (TimeoutException)
        {
            return 1;
        }
    }

    private static async Task<int> RunProductionLoopAsync(WorkerSessionContext context)
    {
        while (true)
        {
            ProtocolEnvelope message;
            try
            {
                message = await context.ReadAsync().ConfigureAwait(false);
            }
            catch (EndOfStreamException)
            {
                return 0;
            }
            catch (IOException)
            {
                return 0;
            }

            switch (message.MessageType)
            {
                case MessageType.ParseJob:
                    ParseJob? job;
                    try
                    {
                        job = JsonSerializer.Deserialize(message.PayloadJson,
                            ProtocolJsonContext.Default.ParseJob);
                    }
                    catch (JsonException)
                    {
                        await SendInvalidJobAsync(context).ConfigureAwait(false);
                        return 4;
                    }

                    if (job is null || job.ProtocolVersion != ProtocolConstants.Version
                        || job.ScanId != context.ScanId || job.JobId != context.JobId
                        || job.Limits.Validate(DateTimeOffset.UtcNow).Count != 0)
                    {
                        await SendInvalidJobAsync(context).ConfigureAwait(false);
                        return 4;
                    }

                    using (var deadline = new CancellationTokenSource())
                    {
                        TimeSpan remaining = job.Limits.DeadlineUtc - DateTimeOffset.UtcNow;
                        deadline.CancelAfter(remaining > TimeSpan.Zero
                            ? remaining
                            : TimeSpan.Zero);
                        var host = new WorkerHost(ParserRegistry.CreateDefault(), context);
                        await host.ProcessJobAsync(job, deadline.Token).ConfigureAwait(false);
                    }
                    return 0;
                case MessageType.CancelJob:
                    return 0;
                default:
                    break;
            }
        }
    }

    private static Task SendInvalidJobAsync(WorkerSessionContext context)
    {
        var failure = new WorkerFailurePayload("invalid_parse_job");
        string payload = JsonSerializer.Serialize(failure,
            ProtocolJsonContext.Default.WorkerFailurePayload);
        return context.SendAsync(MessageType.ParseFailed, payload);
    }
}

internal sealed class WorkerArguments
{
    private WorkerArguments(string pipeName, byte[] nonce, ScanId scanId, JobId jobId,
        string? probeScenario, string? buildSha256Override)
    {
        PipeName = pipeName;
        Nonce = nonce;
        ScanId = scanId;
        JobId = jobId;
        ProbeScenario = probeScenario;
        BuildSha256Override = buildSha256Override;
    }

    public string PipeName { get; }
    public byte[] Nonce { get; }
    public ScanId ScanId { get; }
    public JobId JobId { get; }
    public string? ProbeScenario { get; }
    public string? BuildSha256Override { get; }

    public string BuildSha256 => BuildSha256Override ?? HashOwnExecutable();

    public static WorkerArguments Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i + 1 < args.Length; i += 2)
        {
            if (args[i].StartsWith("--", StringComparison.Ordinal))
            {
                values[args[i][2..]] = args[i + 1];
            }
        }

        if (!values.TryGetValue("pipe", out string? pipe)
            || !values.TryGetValue("nonce", out string? nonceBase64)
            || !values.TryGetValue("scan", out string? scan)
            || !values.TryGetValue("job", out string? job)
            || !Guid.TryParse(scan, out Guid scanGuid)
            || !Guid.TryParse(job, out Guid jobGuid))
        {
            throw new ArgumentException("Missing required worker arguments.");
        }

        byte[] nonce;
        try
        {
            nonce = Convert.FromBase64String(nonceBase64);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid nonce.", ex);
        }

        values.TryGetValue("probe", out string? probe);
        values.TryGetValue("build-sha256", out string? buildOverride);
        return new WorkerArguments(pipe, nonce, new ScanId(scanGuid), new JobId(jobGuid),
            probe, buildOverride);
    }

    private static string HashOwnExecutable()
    {
        string path = Environment.ProcessPath
            ?? throw new InvalidOperationException("Process path is unavailable.");
        byte[] hash = SHA256.HashData(File.ReadAllBytes(path));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

internal sealed class WorkerSessionContext(
    Stream pipe, ScanId scanId, JobId jobId)
{
    private long _nextSequence;

    public Stream Pipe { get; } = pipe;
    public ScanId ScanId { get; } = scanId;
    public JobId JobId { get; } = jobId;
    public long NextSequence => _nextSequence;

    public async Task SendHelloAsync(byte[] nonce, string buildSha256)
    {
        var hello = new HelloPayload(Convert.ToBase64String(nonce), buildSha256);
        string payload = JsonSerializer.Serialize(hello,
            ProtocolJsonContext.Default.HelloPayload);
        // Hello carries no scan/job identity; those are proven by the nonce.
        await SendRawAsync(MessageType.Hello, payload, includeIds: false)
            .ConfigureAwait(false);
    }

    public Task SendAsync(MessageType type, string payloadJson, long? sequenceOverride = null)
    {
        long sequence = sequenceOverride ?? _nextSequence++;
        ProtocolEnvelope envelope = BuildEnvelope(type, payloadJson, includeIds: true,
            sequence);
        return LengthPrefixedJsonProtocol.WriteAsync(Pipe, envelope, CancellationToken.None);
    }

    public byte[] SerializeFrame(MessageType type, string payloadJson, long sequence)
    {
        ProtocolEnvelope envelope = BuildEnvelope(type, payloadJson, includeIds: true,
            sequence);
        return JsonSerializer.SerializeToUtf8Bytes(envelope,
            ProtocolJsonContext.Default.ProtocolEnvelope);
    }

    public async Task WriteRawFrameAsync(byte[] payload)
    {
        byte[] header = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await Pipe.WriteAsync(header).ConfigureAwait(false);
        await Pipe.WriteAsync(payload).ConfigureAwait(false);
        await Pipe.FlushAsync().ConfigureAwait(false);
    }

    public async Task<ProtocolEnvelope> ReadAsync()
    {
        try
        {
            return await LengthPrefixedJsonProtocol.ReadAsync(Pipe, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (ProtocolException)
        {
            throw;
        }
    }

    private Task SendRawAsync(MessageType type, string payloadJson, bool includeIds)
    {
        ProtocolEnvelope envelope = BuildEnvelope(type, payloadJson, includeIds,
            _nextSequence++);
        return LengthPrefixedJsonProtocol.WriteAsync(Pipe, envelope, CancellationToken.None);
    }

    private ProtocolEnvelope BuildEnvelope(MessageType type, string payloadJson,
        bool includeIds, long sequence) =>
        ProtocolEnvelope.Create(type, Guid.NewGuid(), payloadJson,
            includeIds ? ScanId : null, includeIds ? JobId : null) with
        { Sequence = sequence };
}
