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

        await ParseRecursivelyAsync(fs, probe, item.VirtualPath, item.DeclaredLength,
                item, depth: 0, results, cancellationToken)
            .ConfigureAwait(false);
        results.Add(new WorkerJobResult(item.JobId, item.FileId,
            WorkerResultKind.Completed, null, null, null, null, null));
    }

    private async Task ParseRecursivelyAsync(
        Stream stream,
        FormatProbe probe,
        string virtualPath,
        long declaredLength,
        ScanWorkItem item,
        int depth,
        List<WorkerJobResult> results,
        CancellationToken cancellationToken)
    {
        if (depth > item.Limits.MaxDepth)
        {
            results.Add(Gap(item, virtualPath, probe.Format.FormatId,
                GapReason.ArchiveLimit, "depth_exceeded", declaredLength));
            return;
        }

        IFormatParser? parser = _parsers.FirstOrDefault(p => p.CanParse(probe));
        if (parser is null)
        {
            results.Add(Gap(item, virtualPath, probe.Format.FormatId,
                GapReason.UnsupportedFormat, "no_parser", declaredLength));
            return;
        }

        if (stream.CanSeek)
        {
            stream.Position = 0;
        }

        var input = new ParserInput(stream, declaredLength);
        var context = new ParseContext(item.JobId, item.ScanId, virtualPath, item.Limits);

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
                    if (child.StreamFactory is not null)
                    {
                        await using Stream childStream = await child.StreamFactory(cancellationToken)
                            .ConfigureAwait(false);
                        await ParseRecursivelyAsync(
                                childStream,
                                child.Probe,
                                child.VirtualPath,
                                Math.Max(0, child.Probe.DeclaredLength),
                                item,
                                depth + 1,
                                results,
                                cancellationToken)
                            .ConfigureAwait(false);
                    }
                    break;

                case ParserEvent.GapProduced gapEvt:
                    results.Add(new WorkerJobResult(item.JobId, item.FileId,
                        WorkerResultKind.Gap, null, gapEvt.Gap, null, null, null));
                    break;

                case ParserEvent.ParseCompleted:
                    break;
            }
        }
    }

    private static WorkerJobResult Gap(
        ScanWorkItem item,
        string virtualPath,
        string formatId,
        GapReason reason,
        string detailCode,
        long declaredLength)
    {
        var gap = new CoverageGap(
            Guid.NewGuid(), item.ScanId, item.FileId, virtualPath,
            formatId, "parse", reason, detailCode,
            declaredLength, 0, DateTimeOffset.UtcNow);
        return new WorkerJobResult(item.JobId, item.FileId,
            WorkerResultKind.Gap, null, gap, null, null, null);
    }

    private static string? ResolvePhysicalPath(string virtualPath)
    {
        // In-process runner: virtual path is the relative path within scan root.
        // This is resolved by the orchestrator before scheduling.
        return virtualPath;
    }
}
