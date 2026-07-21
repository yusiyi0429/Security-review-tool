using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.IntegrationTests.Scans;

public sealed class CancellationTests
{
    [Fact]
    public async Task cancellation_during_parse_stops_processing()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-cancel-");
        try
        {
            // Create a large text file that takes time to parse.
            string filePath = Path.Combine(root.FullName, "large.txt");
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < 1000; i++)
            {
#pragma warning disable CA1305
                sb.AppendLine($"Line {i}: The quick brown fox jumps over the lazy dog.");
#pragma warning restore CA1305
            }

            await File.WriteAllTextAsync(filePath, sb.ToString(),
                TestContext.Current.CancellationToken);

            var parsers = new IFormatParser[]
            {
                new TextFormatParser(),
            };

            var runner = new InProcessParserRunner(parsers);

            FileId fileId = new(Guid.NewGuid());
            JobId jobId = new(Guid.NewGuid());
            ScanId scanId = new(Guid.NewGuid());

            var item = new ScanWorkItem(
                jobId, scanId, fileId, filePath, "text",
                new FileInfo(filePath).Length,
                ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
                IsOci: false);

            using var cts = new CancellationTokenSource();

            bool cancelled = false;
            int chunkCount = 0;

            try
            {
                await foreach (WorkerJobResult result in runner.ProcessAsync(
                    item, cts.Token))
                {
                    chunkCount++;

                    // Cancel after first chunk.
                    if (chunkCount == 1)
                    {
                        await cts.CancelAsync();
                    }

                    if (result.Kind == WorkerResultKind.Cancelled)
                    {
                        cancelled = true;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }

            Assert.True(cancelled || chunkCount < 1000,
                "Cancellation should stop processing early.");
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task scan_scheduler_cancellation_terminates_workers()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        // Use a fake processor that supports cancellation.
        var processor = new CancellableFakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);
        ScanId scanId = new(Guid.NewGuid());

        scheduler.TryAcquire(scanId);

        var item = new ScanWorkItem(
            new JobId(Guid.NewGuid()), scanId, new FileId(Guid.NewGuid()),
            "test.txt", "text", 100,
            ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
            IsOci: false);

        await scheduler.ScheduleAsync(item, CancellationToken.None);

        // Give the scheduler a moment to start processing.
        await Task.Delay(50);

        scheduler.Cancel();
        scheduler.CompleteAdding();

        var results = new List<WorkerJobResult>();
        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync())
        {
            results.Add(result);
        }

        Assert.NotEmpty(results);
        Assert.Contains(results, r => r.Kind is WorkerResultKind.Cancelled
            or WorkerResultKind.Completed);
    }

    private sealed class CancellableFakeProcessor : IWorkerJobProcessor
    {
        public async IAsyncEnumerable<WorkerJobResult> ProcessAsync(
            ScanWorkItem item,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            bool cancelled = false;

            try
            {
                await Task.Delay(500, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }

            if (cancelled)
            {
                yield return new WorkerJobResult(item.JobId, item.FileId,
                    WorkerResultKind.Cancelled, null, null, null, null,
                    WorkerFailure.Cancelled);
            }
            else
            {
                yield return new WorkerJobResult(item.JobId, item.FileId,
                    WorkerResultKind.Completed, null, null, null, null, null);
            }
        }
    }
}
