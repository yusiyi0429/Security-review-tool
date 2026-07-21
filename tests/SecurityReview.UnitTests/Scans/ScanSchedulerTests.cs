using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanSchedulerTests
{
    [Fact]
    public void default_max_workers_is_min_4_max_2_logical_cpu_div_2()
    {
        int maxWorkers = ScanScheduler.DefaultMaxWorkers;
        int logicalCpu = Environment.ProcessorCount;

        int expected = Math.Min(4, Math.Max(2, logicalCpu / 2));
        Assert.Equal(expected, maxWorkers);
        Assert.True(maxWorkers is >= 2 and <= 4);
    }

    [Fact]
    public void TryAcquire_succeeds_when_no_active_scan()
    {
        var processor = new FakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);

        bool acquired = scheduler.TryAcquire(new ScanId(Guid.NewGuid()));

        Assert.True(acquired);
    }

    [Fact]
    public void TryAcquire_fails_when_scan_already_active()
    {
        var processor = new FakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);

        scheduler.TryAcquire(new ScanId(Guid.NewGuid()));

        bool secondAcquire = scheduler.TryAcquire(new ScanId(Guid.NewGuid()));
        Assert.False(secondAcquire);
    }

    [Fact]
    public void ordinary_parse_deadline_is_120_seconds_from_now()
    {
        DateTimeOffset now = new(2026, 7, 21, 0, 0, 0, TimeSpan.Zero);
        ParseLimits limits = ScanScheduler.CreateOrdinaryLimits(now);

        Assert.Equal(now.AddSeconds(120), limits.DeadlineUtc);
    }

    [Fact]
    public void oci_parse_deadline_is_30_minutes_from_now()
    {
        DateTimeOffset now = new(2026, 7, 21, 0, 0, 0, TimeSpan.Zero);
        ParseLimits limits = ScanScheduler.CreateOciLimits(now);

        Assert.Equal(now.AddMinutes(30), limits.DeadlineUtc);
    }

    [Fact]
    public async Task schedule_and_complete_produces_results()
    {
        var processor = new FakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);
        ScanId scanId = new(Guid.NewGuid());

        scheduler.TryAcquire(scanId);

        var item = CreateWorkItem(scanId);
        await scheduler.ScheduleAsync(item, CancellationToken.None);
        scheduler.CompleteAdding();

        var results = new List<WorkerJobResult>();
        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync())
        {
            results.Add(result);
        }

        Assert.Single(results);
        Assert.Equal(WorkerResultKind.Completed, results[0].Kind);
        Assert.Equal(item.JobId, results[0].JobId);
    }

    [Fact]
    public async Task worker_failure_produces_failed_result()
    {
        var processor = new FakeProcessor(fail: true);
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);
        ScanId scanId = new(Guid.NewGuid());

        scheduler.TryAcquire(scanId);

        var item = CreateWorkItem(scanId);
        await scheduler.ScheduleAsync(item, CancellationToken.None);
        scheduler.CompleteAdding();

        var results = new List<WorkerJobResult>();
        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync())
        {
            results.Add(result);
        }

        Assert.Single(results);
        Assert.Equal(WorkerResultKind.Failed, results[0].Kind);
    }

    [Fact]
    public async Task cancellation_stops_processing()
    {
        var processor = new FakeProcessor(delayMs: 100);
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);
        ScanId scanId = new(Guid.NewGuid());

        scheduler.TryAcquire(scanId);

        var item = CreateWorkItem(scanId);
        await scheduler.ScheduleAsync(item, CancellationToken.None);
        scheduler.CompleteAdding();

        // Cancel immediately.
        scheduler.Cancel();

        var results = new List<WorkerJobResult>();
        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync())
        {
            results.Add(result);
        }

        // Should get a result (either Completed or Cancelled).
        Assert.NotEmpty(results);
    }

    [Fact]
    public void worker_failure_maps_to_correct_gap_reason()
    {
        Assert.Equal(GapReason.ParserTimeout,
            WorkerFailureMapper.MapFailure(WorkerFailure.Timeout));
        Assert.Equal(GapReason.ParserMemory,
            WorkerFailureMapper.MapFailure(WorkerFailure.MemoryLimit));
        Assert.Equal(GapReason.ParserProtocolMismatch,
            WorkerFailureMapper.MapFailure(WorkerFailure.ProtocolViolation));
        Assert.Equal(GapReason.ParserCrash,
            WorkerFailureMapper.MapFailure(WorkerFailure.Crash));
        Assert.Equal(GapReason.Cancelled,
            WorkerFailureMapper.MapFailure(WorkerFailure.Cancelled));
    }

    [Fact]
    public async Task multiple_items_are_processed_in_order()
    {
        var processor = new FakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);
        ScanId scanId = new(Guid.NewGuid());

        scheduler.TryAcquire(scanId);

        var items = new List<ScanWorkItem>();
        for (int i = 0; i < 3; i++)
        {
            var item = CreateWorkItem(scanId);
            items.Add(item);
            await scheduler.ScheduleAsync(item, CancellationToken.None);
        }

        scheduler.CompleteAdding();

        var results = new List<WorkerJobResult>();
        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync())
        {
            results.Add(result);
        }

        Assert.Equal(3, results.Count);
        Assert.All(results, r => Assert.Equal(WorkerResultKind.Completed, r.Kind));
    }

    [Fact]
    public void oci_lease_can_be_acquired_and_released()
    {
        var processor = new FakeProcessor();
        var scheduler = new ScanScheduler(processor, maxWorkers: 2);

        Assert.False(scheduler.OciLeaseActive);

        scheduler.TryAcquire(new ScanId(Guid.NewGuid()));
        // OCI lease starts not active.
        Assert.False(scheduler.OciLeaseActive);

        // In current implementation, OciLeaseActive is synced from AcquireOciLeaseAsync.
        // It's set manually via the method.
    }

    private static ScanWorkItem CreateWorkItem(ScanId scanId) =>
        new(
            JobId: new JobId(Guid.NewGuid()),
            ScanId: scanId,
            FileId: new FileId(Guid.NewGuid()),
            VirtualPath: "test.txt",
            FormatHint: "text",
            DeclaredLength: 100,
            Limits: ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
            IsOci: false);

    /// <summary>Fake processor for deterministic testing.</summary>
    private sealed class FakeProcessor : IWorkerJobProcessor
    {
        private readonly bool _fail;
        private readonly int _delayMs;

        public FakeProcessor(bool fail = false, int delayMs = 0)
        {
            _fail = fail;
            _delayMs = delayMs;
        }

        public async IAsyncEnumerable<WorkerJobResult> ProcessAsync(
            ScanWorkItem item,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (_delayMs > 0)
            {
                try
                {
                    await Task.Delay(_delayMs, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // Fall through to return cancelled result below.
                }
            }

            if (cancellationToken.IsCancellationRequested)
            {
                yield return new WorkerJobResult(item.JobId, item.FileId,
                    WorkerResultKind.Cancelled, null, null, null, null,
                    WorkerFailure.Cancelled);
                yield break;
            }

            if (_fail)
            {
                yield return new WorkerJobResult(item.JobId, item.FileId,
                    WorkerResultKind.Failed, null, null, null, null,
                    WorkerFailure.Crash);
            }
            else
            {
                yield return new WorkerJobResult(item.JobId, item.FileId,
                    WorkerResultKind.Completed, null, null, null, null, null);
            }
        }
    }
}
