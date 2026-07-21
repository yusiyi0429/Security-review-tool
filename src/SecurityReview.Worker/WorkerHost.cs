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

            // Select parser.
            IFormatParser? parser = _registry.FindParser(probe);
            if (parser is null)
            {
                await _session.SendAsync(MessageType.GapProduced,
                    SerializeGapPayload(GapReason.UnsupportedFormat,
                        $"no_parser:{probe.Format.FormatId}"))
                    .ConfigureAwait(false);

                await _session.SendAsync(MessageType.ParseCompleted, "{}")
                    .ConfigureAwait(false);
                return true;
            }

            // Re-seek after probe.
            inputStream.Position = 0;

            var input = new ParserInput(inputStream, job.DeclaredLength);
            var context = new ParseContext(job.JobId, job.ScanId,
                job.DisplayVirtualPath, job.Limits);

            long sequence = 0;
            await foreach (ParserEvent evt in parser.ParseAsync(input, context, cancellationToken)
               .ConfigureAwait(false))
            {
                switch (evt)
                {
                    case ParserEvent.ChunkProduced chunk:
                        string chunkPayload = System.Text.Json.JsonSerializer.Serialize(
                            chunk.Chunk, ProtocolJsonContext.Default.ContentChunk);
                        await _session.SendAsync(MessageType.ContentChunk, chunkPayload,
                            sequence++).ConfigureAwait(false);
                        break;

                    case ParserEvent.ChildDiscovered child:
                        string childPayload = System.Text.Json.JsonSerializer.Serialize(
                            new
                            {
                                virtualPath = child.VirtualPath,
                                formatId = child.Probe.Format.FormatId,
                                confidence = child.Probe.Format.Confidence,
                                declaredLength = child.Probe.DeclaredLength
                            });
                        await _session.SendAsync(MessageType.GapProduced, childPayload)
                            .ConfigureAwait(false);
                        break;

                    case ParserEvent.GapProduced gapEvt:
                        string gapPayload = System.Text.Json.JsonSerializer.Serialize(
                            new
                            {
                                gapId = gapEvt.Gap.GapId,
                                reason = gapEvt.Gap.Reason.ToString(),
                                detailCode = gapEvt.Gap.DetailCode,
                                virtualPath = gapEvt.Gap.VirtualPath,
                                formatId = gapEvt.Gap.FormatId
                            });
                        await _session.SendAsync(MessageType.GapProduced, gapPayload)
                            .ConfigureAwait(false);
                        break;

                    case ParserEvent.ParseCompleted:
                        await _session.SendAsync(MessageType.ParseCompleted, "{}")
                            .ConfigureAwait(false);
                        break;
                }
            }

            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            try
            {
                string failPayload = SerializeGapPayload(GapReason.Corrupt,
                    $"unhandled:{ex.GetType().Name}");
                await _session.SendAsync(MessageType.GapProduced, failPayload)
                    .ConfigureAwait(false);
            }
            catch
            {
                // Best effort.
            }

            return true;
        }
    }

    private static FileStream OpenInputStream(ParseJob job)
    {
        // In production, the input handle is a brokered OS file handle.
        // For in-process testing and smoke CLI, we resolve the virtual path.
        string path = job.DisplayVirtualPath;
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Input file not found: {path}", path);
        }

        return File.OpenRead(path);
    }

    private static string SerializeGapPayload(GapReason reason, string detailCode) =>
        System.Text.Json.JsonSerializer.Serialize(
            new { reason = reason.ToString(), detailCode });
}
