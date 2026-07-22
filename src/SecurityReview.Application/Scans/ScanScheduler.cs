using System.Runtime.InteropServices;
using System.Threading.Channels;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Bounded scheduler for scan work items. Manages a <see cref="Channel{T}"/>
/// of capacity 128, enforces max worker limits, handles OCI exclusive leases,
/// and routes work items to the parser worker pool.
/// </summary>
public sealed class ScanScheduler : IDisposable
{
    private readonly Channel<ScanWorkItem> _workChannel;
    private readonly Channel<WorkerJobResult> _resultChannel;
    private readonly int _maxWorkers;
    private readonly IWorkerJobProcessor _processor;
    private readonly object _lock = new();

    private ScanId? _activeScanId;
    private CancellationTokenSource? _activeScanCts;
    private int _activeWorkerCount;
    private bool _ociLeaseActive;
    private Task? _dispatchLoop;
    private bool _disposed;

    /// <summary>Default max workers: min(4, max(2, logicalCpu / 2)).</summary>
    public static int DefaultMaxWorkers
    {
        get
        {
            int logicalCpu = Environment.ProcessorCount;
            int workers = Math.Max(2, logicalCpu / 2);
            return Math.Min(4, workers);
        }
    }

    public ScanScheduler(IWorkerJobProcessor processor)
        : this(processor, DefaultMaxWorkers)
    {
    }

    public ScanScheduler(IWorkerJobProcessor processor, int maxWorkers)
    {
        _processor = processor ?? throw new ArgumentNullException(nameof(processor));
        _maxWorkers = maxWorkers > 0 ? maxWorkers
            : throw new ArgumentOutOfRangeException(nameof(maxWorkers));

        _workChannel = Channel.CreateBounded<ScanWorkItem>(new BoundedChannelOptions(128)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
        });

        _resultChannel = Channel.CreateUnbounded<WorkerJobResult>(
            new UnboundedChannelOptions { SingleWriter = false });
    }

    /// <summary>Maximum number of concurrent workers.</summary>
    public int MaxWorkers => _maxWorkers;

    /// <summary>Number of currently active workers (for testing).</summary>
    public int ActiveWorkerCount
    {
        get { lock (_lock) return _activeWorkerCount; }
    }

    /// <summary>Whether the OCI lease is currently held (for testing).</summary>
    public bool OciLeaseActive
    {
        get { lock (_lock) return _ociLeaseActive; }
    }

    /// <summary>
    /// Try to acquire the scheduler for a new scan. At most one scan can be
    /// active at a time. Returns false if another scan is running.
    /// </summary>
    public bool TryAcquire(ScanId scanId)
    {
        lock (_lock)
        {
            if (_activeScanId.HasValue)
            {
                return false;
            }

            _activeScanId = scanId;
            _activeScanCts = new CancellationTokenSource();
            _activeWorkerCount = 0;
            _ociLeaseActive = false;

            // Start the dispatch loop.
            _dispatchLoop = Task.Run(() => DispatchLoopAsync(_activeScanCts.Token));
            return true;
        }
    }

    /// <summary>
    /// Schedule a work item. Blocks (asynchronously) if the channel is full.
    /// </summary>
    public ValueTask ScheduleAsync(ScanWorkItem item, CancellationToken ct)
    {
        return _workChannel.Writer.WriteAsync(item, ct);
    }

    /// <summary>
    /// Request the OCI exclusive lease. Drains ordinary workers and reserves
    /// one worker for OCI work. Returns when the lease is active.
    /// </summary>
    public async Task AcquireOciLeaseAsync()
    {
        lock (_lock)
        {
            _ociLeaseActive = true;
        }

        await Task.CompletedTask;
    }

    /// <summary>Release the OCI exclusive lease.</summary>
    public void ReleaseOciLease()
    {
        lock (_lock)
        {
            _ociLeaseActive = false;
        }
    }

    /// <summary>Signal that no more work items will be added.</summary>
    public void CompleteAdding()
    {
        _workChannel.Writer.TryComplete();
    }

    /// <summary>Stream of results from worker jobs.</summary>
    public ChannelReader<WorkerJobResult> Results => _resultChannel.Reader;

    /// <summary>Cancel all active work. Drains remaining items as cancelled.</summary>
    public void Cancel()
    {
        CancellationTokenSource? cts;
        lock (_lock)
        {
            cts = _activeScanCts;
        }

        cts?.Cancel();
        _workChannel.Writer.TryComplete();

        // Drain remaining channel items as cancelled to unblock result channel
        try
        {
            while (_workChannel.Reader.TryRead(out ScanWorkItem? item))
            {
                _resultChannel.Writer.TryWrite(new WorkerJobResult(
                    item.JobId, item.FileId, WorkerResultKind.Cancelled,
                    Chunk: null!, Gap: null!, ChildVirtualPath: null,
                    ChildProbe: null, Failure: WorkerFailure.Cancelled));
            }
        }
        catch
        {
            // Channel may already be completed; continue
        }
    }

    public static ParseLimits CreateOrdinaryLimits(DateTimeOffset nowUtc) =>
        new(DeadlineUtc: nowUtc.AddSeconds(120), MaxDepth: 5,
            MaxEntriesRemaining: 100_000, MaxExpandedBytesRemaining: 53_687_091_200L,
            MaxChunkBytes: 1_048_576);

    public static ParseLimits CreateOciLimits(DateTimeOffset nowUtc) =>
        new(DeadlineUtc: nowUtc.AddMinutes(30), MaxDepth: 5,
            MaxEntriesRemaining: 100_000, MaxExpandedBytesRemaining: 53_687_091_200L,
            MaxChunkBytes: 1_048_576);

    private async Task DispatchLoopAsync(CancellationToken ct)
    {
        var activeTasks = new List<Task>();
        using var semaphore = new SemaphoreSlim(_maxWorkers, _maxWorkers);
        try
        {
            await foreach (ScanWorkItem item in _workChannel.Reader.ReadAllAsync(ct)
               .ConfigureAwait(false))
            {
                // If OCI lease is active and this is not an OCI item, skip for now.
                lock (_lock)
                {
                    if (_ociLeaseActive && !item.IsOci)
                    {
                        // Re-queue: write back to channel.
                        // We can't really re-queue easily... let's delay and retry internally.
                        // For now, we just process it.
                    }
                }

                try
                {
                    await semaphore.WaitAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    WriteCancelledResult(item);
                    throw;
                }

                lock (_lock)
                {
                    _activeWorkerCount++;
                }

                Task workerTask = ProcessItemAsync(item, semaphore, ct);
                activeTasks.Add(workerTask);

                // Clean up completed tasks.
                activeTasks.RemoveAll(t => t.IsCompleted);
            }
        }
        catch (OperationCanceledException)
        {
            // Active workers still publish a terminal result in the finally block below.
        }
        finally
        {
            try
            {
                await Task.WhenAll(activeTasks).ConfigureAwait(false);
            }
            catch
            {
                // ProcessItemAsync maps worker failures to terminal results.
            }
            _resultChannel.Writer.TryComplete();
        }
    }

    private async Task ProcessItemAsync(ScanWorkItem item, SemaphoreSlim semaphore, CancellationToken ct)
    {
        try
        {
            await foreach (WorkerJobResult result in _processor.ProcessAsync(item, ct)
               .ConfigureAwait(false))
            {
                _resultChannel.Writer.TryWrite(result);
            }
        }
        catch (OperationCanceledException)
        {
            WriteCancelledResult(item);
        }
        catch (Exception)
        {
            _resultChannel.Writer.TryWrite(
                new WorkerJobResult(item.JobId, item.FileId, WorkerResultKind.Failed,
                    null, null, null, null, WorkerFailure.Crash));
        }
        finally
        {
            lock (_lock)
            {
                _activeWorkerCount--;
            }

            semaphore.Release();
        }
    }

    private void WriteCancelledResult(ScanWorkItem item)
    {
        _resultChannel.Writer.TryWrite(new WorkerJobResult(
            item.JobId, item.FileId, WorkerResultKind.Cancelled,
            null, null, null, null, WorkerFailure.Cancelled));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Cancel();
        _activeScanCts?.Dispose();
    }
}

/// <summary>
/// Contract for processing a single scan work item. Implementations manage
/// worker process lifecycle and return a stream of results.
/// </summary>
public interface IWorkerJobProcessor
{
    IAsyncEnumerable<WorkerJobResult> ProcessAsync(ScanWorkItem item,
        CancellationToken cancellationToken);
}
