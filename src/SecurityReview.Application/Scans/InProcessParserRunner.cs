using System.Runtime.CompilerServices;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Application.Scans;

/// <summary>
/// In-process implementation of <see cref="IWorkerJobProcessor"/> that runs
/// parsers directly in the current process. Used for integration testing
/// and smoke CLI; NOT for production (no sandbox isolation).
/// </summary>
public sealed class InProcessParserRunner : IWorkerJobProcessor
{
    private readonly IReadOnlyList<IFormatParser> _parsers;

    public InProcessParserRunner(IReadOnlyList<IFormatParser> parsers)
    {
        _parsers = parsers ?? throw new ArgumentNullException(nameof(parsers));
    }

    public async IAsyncEnumerable<WorkerJobResult> ProcessAsync(
        ScanWorkItem item,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Collect results outside try/catch so we can yield after.
        List<WorkerJobResult> results = new();

        try
        {
            await ProcessItemCoreAsync(item, results, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            results.Add(new WorkerJobResult(item.JobId, item.FileId,
                WorkerResultKind.Cancelled, null, null, null, null,
                WorkerFailure.Cancelled));
        }
        catch (Exception ex)
        {
            var failGap = new CoverageGap(
                Guid.NewGuid(), item.ScanId, item.FileId, item.VirtualPath,
                item.FormatHint, "parse", GapReason.Corrupt,
                $"exception:{ex.GetType().Name}", item.DeclaredLength, 0,
                DateTimeOffset.UtcNow);

            results.Add(new WorkerJobResult(item.JobId, item.FileId,
                WorkerResultKind.Failed, null, failGap, null, null, null));
        }

        foreach (WorkerJobResult result in results)
        {
            yield return result;
        }
    }

    private async Task ProcessItemCoreAsync(
        ScanWorkItem item,
        List<WorkerJobResult> results,
        CancellationToken cancellationToken)
    {
        string? resolvedPath = ResolvePhysicalPath(item.InputFilePath ?? item.VirtualPath);
        if (resolvedPath is null || !File.Exists(resolvedPath))
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), item.ScanId, item.FileId, item.VirtualPath,
                item.FormatHint, "inventory", GapReason.AccessDenied,
                "file_not_found", item.DeclaredLength, 0, DateTimeOffset.UtcNow);

            results.Add(new WorkerJobResult(item.JobId, item.FileId,
                WorkerResultKind.Failed, null, gap, null, null, null));
            return;
        }

        await using FileStream fs = File.OpenRead(resolvedPath);

        // Probe the format.
        FormatProbe probe = await FormatSniffer.ProbeAsync(
            fs, Path.GetExtension(item.VirtualPath), cancellationToken)
            .ConfigureAwait(false);

        // Select parser.
        IFormatParser? parser = _parsers.FirstOrDefault(p => p.CanParse(probe));
        if (parser is null)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), item.ScanId, item.FileId, item.VirtualPath,
                probe.Format.FormatId, "sniff", GapReason.UnsupportedFormat,
                "no_parser", item.DeclaredLength, 0, DateTimeOffset.UtcNow);

            results.Add(new WorkerJobResult(item.JobId, item.FileId,
                WorkerResultKind.Gap, null, gap, null, null, null));
            return;
        }

        // Re-seek after probe.
        fs.Position = 0;
        var input = new ParserInput(fs, item.DeclaredLength);
        var context = new ParseContext(item.JobId, item.ScanId, item.VirtualPath, item.Limits);

        await foreach (ParserEvent evt in parser.ParseAsync(input, context, cancellationToken)
           .ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();

            switch (evt)
            {
                case ParserEvent.ChunkProduced chunk:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Chunk, chunk.Chunk, null, null, null, null));
                    break;

                case ParserEvent.ChildDiscovered child:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.ChildDiscovered, null, null,
                        child.VirtualPath, child.Probe, null));
                    break;

                case ParserEvent.GapProduced gapEvt:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Gap, null, gapEvt.Gap, null, null, null));
                    break;

                case ParserEvent.ParseCompleted:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Completed, null, null, null, null, null));
                    break;
            }
        }
    }

    private static string? ResolvePhysicalPath(string virtualPath)
    {
        // In-process runner: virtual path is the relative path within scan root.
        // This is resolved by the orchestrator before scheduling.
        return virtualPath;
    }
}
