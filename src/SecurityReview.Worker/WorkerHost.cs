using Microsoft.Win32.SafeHandles;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.Worker;

/// <summary>
/// Manages the parse lifecycle inside a worker process. Receives
/// <see cref="ParseJob"/> messages via the protocol pipe, selects the
/// appropriate parser, executes the parse, and sends results back.
/// </summary>
internal sealed class WorkerHost
{
    private readonly ParserRegistry _registry;
    private readonly WorkerSessionContext _session;

    public WorkerHost(ParserRegistry registry, WorkerSessionContext session)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _session = session ?? throw new ArgumentNullException(nameof(session));
    }

    /// <summary>
    /// Process a single <see cref="ParseJob"/>. Runs the parse and sends
    /// results back through the session. Returns true if the worker should
    /// continue receiving more jobs; false if the session should end.
    /// </summary>
    public async Task<bool> ProcessJobAsync(ParseJob job, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);

        try
        {
            // Open the input handle as a stream.
            await using Stream inputStream = OpenInputStream(job);

            // Probe the format.
            FormatProbe probe = await FormatSniffer.ProbeAsync(
                inputStream, Path.GetExtension(job.DisplayVirtualPath), cancellationToken)
                .ConfigureAwait(false);

            await ParseRecursivelyAsync(
                    inputStream,
                    probe,
                    job.DisplayVirtualPath,
                    job.DeclaredLength,
                    job,
                    depth: 0,
                    cancellationToken)
                .ConfigureAwait(false);

            // Child parsers also emit ParseCompleted. The protocol has one
            // terminal message per worker job, so only the host emits it.
            await _session.SendAsync(MessageType.ParseCompleted, "{}")
                .ConfigureAwait(false);

            return false;
        }
        catch (OperationCanceledException)
        {
            await TrySendFailureAsync("timeout").ConfigureAwait(false);
            return false;
        }
        catch (Exception ex)
        {
            await TrySendFailureAsync($"exception:{ex.GetType().Name}")
                .ConfigureAwait(false);
            return false;
        }
    }

    private async Task ParseRecursivelyAsync(
        Stream stream,
        FormatProbe probe,
        string virtualPath,
        long declaredLength,
        ParseJob job,
        int depth,
        CancellationToken cancellationToken)
    {
        if (depth > job.Limits.MaxDepth)
        {
            await SendGapAsync(GapReason.ArchiveLimit, "depth_exceeded",
                virtualPath, probe.Format.FormatId, declaredLength, 0)
                .ConfigureAwait(false);
            return;
        }

        IFormatParser? parser = _registry.FindParser(probe);
        if (parser is null)
        {
            await SendGapAsync(GapReason.UnsupportedFormat,
                $"no_parser:{probe.Format.FormatId}", virtualPath,
                probe.Format.FormatId, declaredLength, 0)
                .ConfigureAwait(false);
            return;
        }

        if (stream.CanSeek)
        {
            stream.Position = 0;
        }

        var input = new ParserInput(stream, declaredLength);
        var context = new ParseContext(job.JobId, job.ScanId, virtualPath, job.Limits);

        await foreach (ParserEvent evt in parser.ParseAsync(input, context, cancellationToken)
            .ConfigureAwait(false))
        {
            switch (evt)
            {
                case ParserEvent.ChunkProduced chunk:
                    string chunkPayload = System.Text.Json.JsonSerializer.Serialize(
                        chunk.Chunk, ProtocolJsonContext.Default.ContentChunk);
                    await _session.SendAsync(MessageType.ContentChunk, chunkPayload)
                        .ConfigureAwait(false);
                    break;

                case ParserEvent.ChildDiscovered child:
                    var childMessage = new WorkerChildPayload(
                        child.VirtualPath,
                        child.Probe.Format.FormatId,
                        child.Probe.Format.Confidence,
                        child.Probe.DeclaredLength);
                    string childPayload = System.Text.Json.JsonSerializer.Serialize(
                        childMessage, ProtocolJsonContext.Default.WorkerChildPayload);
                    await _session.SendAsync(MessageType.ChildDiscovered, childPayload)
                        .ConfigureAwait(false);

                    if (child.StreamFactory is not null)
                    {
                        await using Stream childStream = await child.StreamFactory(cancellationToken)
                            .ConfigureAwait(false);
                        long childLength = Math.Max(0, child.Probe.DeclaredLength);
                        await ParseRecursivelyAsync(
                                childStream,
                                child.Probe,
                                child.VirtualPath,
                                childLength,
                                job,
                                depth + 1,
                                cancellationToken)
                            .ConfigureAwait(false);
                    }
                    break;

                case ParserEvent.GapProduced gapEvt:
                    await SendGapAsync(
                            gapEvt.Gap.Reason,
                            gapEvt.Gap.DetailCode,
                            gapEvt.Gap.VirtualPath,
                            gapEvt.Gap.FormatId,
                            gapEvt.Gap.PlannedBytes,
                            gapEvt.Gap.ProcessedBytes)
                        .ConfigureAwait(false);
                    break;

                case ParserEvent.ParseCompleted:
                    break;
            }
        }
    }

    private Task SendGapAsync(
        GapReason reason,
        string detailCode,
        string? virtualPath,
        string? formatId,
        long? plannedBytes,
        long? processedBytes) =>
        _session.SendAsync(MessageType.GapProduced,
            SerializeGapPayload(reason, detailCode, virtualPath, formatId,
                plannedBytes, processedBytes));

    private async Task TrySendFailureAsync(string errorCode)
    {
        try
        {
            var failure = new WorkerFailurePayload(errorCode);
            string payload = System.Text.Json.JsonSerializer.Serialize(
                failure, ProtocolJsonContext.Default.WorkerFailurePayload);
            await _session.SendAsync(MessageType.ParseFailed, payload)
                .ConfigureAwait(false);
        }
        catch
        {
            // The parent also enforces the deadline and terminates the worker.
        }
    }

    private static FileStream OpenInputStream(ParseJob job)
    {
        if (job.InputHandle is 0 or -1)
            throw new IOException("The brokered input handle is invalid.");

        var handle = new SafeFileHandle((nint)job.InputHandle, ownsHandle: true);
        try
        {
            return new FileStream(handle, FileAccess.Read, bufferSize: 81_920,
                isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static string SerializeGapPayload(
        GapReason reason,
        string detailCode,
        string? virtualPath,
        string? formatId,
        long? plannedBytes,
        long? processedBytes)
    {
        var payload = new WorkerGapPayload(reason.ToString(), detailCode,
            virtualPath, formatId, plannedBytes, processedBytes);
        return System.Text.Json.JsonSerializer.Serialize(
            payload, ProtocolJsonContext.Default.WorkerGapPayload);
    }
}
