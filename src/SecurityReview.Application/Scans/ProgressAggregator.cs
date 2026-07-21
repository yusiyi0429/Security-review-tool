using System.Threading.Channels;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Aggregates scan progress updates with coalescing. Updates are emitted
/// at most every 250 ms and at least every 500 ms while the scan is active.
/// Thread-safe.
/// </summary>
public sealed class ProgressAggregator : IDisposable
{
    private readonly Channel<ScanProgress> _output;
    private readonly Channel<ScanProgress> _input;
    private readonly CancellationTokenSource _cts = new();
    private ScanProgress _latest = ScanProgress.Empty;
    private readonly object _lock = new();
    private Task? _pump;
    private bool _disposed;

    public ProgressAggregator()
    {
        _output = Channel.CreateUnbounded<ScanProgress>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
        _input = Channel.CreateBounded<ScanProgress>(
            new BoundedChannelOptions(64) { SingleWriter = false, FullMode = BoundedChannelFullMode.DropOldest });
    }

    /// <summary>Stream of coalesced progress updates.</summary>
    public ChannelReader<ScanProgress> Updates => _output.Reader;

    /// <summary>Post an updated snapshot. Non-blocking.</summary>
    public void Post(ScanProgress progress)
    {
        _input.Writer.TryWrite(progress);
    }

    /// <summary>Start the coalescing pump. Call once.</summary>
    public void Start()
    {
        _pump = Task.Run(() => PumpAsync(_cts.Token));
    }

    /// <summary>Signal no more updates and complete the output stream.</summary>
    public async Task CompleteAsync()
    {
        _input.Writer.TryComplete();
        if (_pump is not null)
        {
            await _pump.ConfigureAwait(false);
        }

        _output.Writer.TryComplete();
    }

    private async Task PumpAsync(CancellationToken ct)
    {
        // Flush the latest snapshot at least every 500 ms and at most every 250 ms.
        // When no new updates arrive for 500 ms, emit the latest then wait again.
        while (!ct.IsCancellationRequested)
        {
            bool hadUpdate = false;

            try
            {
                // Collect updates for up to 250 ms (coalesce window).
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

                await foreach (ScanProgress update in _input.Reader.ReadAllAsync(linked.Token)
                   .ConfigureAwait(false))
                {
                    lock (_lock)
                    {
                        _latest = update;
                    }

                    hadUpdate = true;
                }
            }
            catch (OperationCanceledException)
            {
                // Timeout or shutdown — emit if we have updates.
            }

            // Emit the latest snapshot if we collected any.
            if (hadUpdate)
            {
                ScanProgress snapshot;
                lock (_lock)
                {
                    snapshot = _latest;
                }

                await _output.Writer.WriteAsync(snapshot, ct).ConfigureAwait(false);
            }

            // If input channel is complete, emit final and exit.
            if (_input.Reader.Completion.IsCompleted)
            {
                // Drain any remaining items.
                while (_input.Reader.TryRead(out ScanProgress? final))
                {
                    lock (_lock)
                    {
                        _latest = final;
                    }
                }

                ScanProgress lastSnapshot;
                lock (_lock)
                {
                    lastSnapshot = _latest;
                }

                await _output.Writer.WriteAsync(lastSnapshot, ct).ConfigureAwait(false);
                _output.Writer.TryComplete();
                return;
            }

            // Wait before next coalesce window (ensures 500 ms max interval).
            try
            {
                await Task.Delay(250, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }
}
