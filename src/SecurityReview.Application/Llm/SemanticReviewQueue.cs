using System.Threading.Channels;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Default <see cref="ISemanticReviewQueue"/>. Holds a
/// <see cref="Channel{T}"/> of <see cref="SemanticQueueItem"/> with a
/// capacity of <see cref="SemanticReviewQueueOptions.FixedCapacity"/>
/// (1000), spawns
/// <see cref="SemanticReviewQueueOptions.MinConsumers"/>–<see cref="SemanticReviewQueueOptions.MaxConsumers"/>
/// consumer tasks, and processes each item under a single
/// <see cref="ISemanticReviewer"/>. Unresolved results are persisted
/// only when the candidate is still current; cancelled items are
/// surfaced in the progress counters but never persisted.
///
/// This type is safe for one producer, multiple consumers. The
/// producer side is <see cref="EnqueueAsync"/>; the consumer side is
/// <see cref="RunAsync"/>. The queue is single-use: once
/// <see cref="RunAsync"/> completes the channel is closed and no
/// further enqueues are accepted.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Naming", "CA1711", Justification = "Domain noun is 'queue'; renaming would obscure the semantic-review flow.")]
public sealed class SemanticReviewQueue : ISemanticReviewQueue, IDisposable
{
    private readonly Channel<SemanticQueueItem> _channel;
    private readonly ISemanticReviewer _reviewer;
    private readonly ISemanticCandidateLifetime _lifetime;
    private readonly ISemanticReviewPersister _persister;
    private readonly ISemanticReviewProgressSink _progressSink;
    private readonly SemanticReviewQueueOptions _options;
    private readonly CancellationTokenSource _internalCts = new();
    private readonly object _gate = new();

    private int _activeCount;
    private int _completedCount;
    private int _failedCount;
    private int _cancelledCount;
    private DateTimeOffset _lastUpdatedAtUtc = DateTimeOffset.UtcNow;
    private bool _cancelled;
    private bool _completedAdding;
    private bool _disposed;

    public SemanticReviewQueue(
        SemanticReviewQueueOptions options,
        ISemanticReviewer reviewer,
        ISemanticCandidateLifetime lifetime,
        ISemanticReviewPersister persister,
        ISemanticReviewProgressSink progressSink)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(reviewer);
        ArgumentNullException.ThrowIfNull(lifetime);
        ArgumentNullException.ThrowIfNull(persister);
        ArgumentNullException.ThrowIfNull(progressSink);

        _options = NormalizeOptions(options);
        _reviewer = reviewer;
        _lifetime = lifetime;
        _persister = persister;
        _progressSink = progressSink;

        _channel = Channel.CreateBounded<SemanticQueueItem>(
            new BoundedChannelOptions(_options.Capacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = false,
                SingleReader = false,
            });
    }

    public int MaxConsumers => _options.MaxConsumerCount;
    public int Capacity => _options.Capacity;
    public int PendingCount => _channel.Reader.Count;

    public ValueTask<bool> EnqueueAsync(SemanticQueueItem item, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!item.RequiresSemanticReview)
            return ValueTask.FromResult(false);

        if (cancellationToken.IsCancellationRequested)
            return ValueTask.FromResult(false);

        lock (_gate)
        {
            if (_cancelled || _completedAdding)
                return ValueTask.FromResult(false);

            // TryWrite returns false when the channel is full.
            if (!_channel.Writer.TryWrite(item))
                return ValueTask.FromResult(false);
        }

        PublishProgress();
        return ValueTask.FromResult(true);
    }

    public void CompleteAdding()
    {
        lock (_gate)
        {
            if (_completedAdding) return;
            _completedAdding = true;
        }
        _channel.Writer.TryComplete();
    }

    public void Cancel()
    {
        lock (_gate)
        {
            if (_cancelled) return;
            _cancelled = true;
        }
        try { _internalCts.Cancel(); } catch (ObjectDisposedException) { }
        _channel.Writer.TryComplete();
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var consumers = new Task[_options.MaxConsumerCount];
        for (int i = 0; i < consumers.Length; i++)
        {
            consumers[i] = Task.Run(
                () => ConsumerLoopAsync(_internalCts.Token),
                CancellationToken.None);
        }
        return Task.WhenAll(consumers);
    }

    public SemanticQueueProgress GetProgress()
    {
        lock (_gate)
        {
            return new SemanticQueueProgress(
                PendingCount: _channel.Reader.Count,
                ActiveCount: _activeCount,
                CompletedCount: _completedCount,
                FailedCount: _failedCount,
                CancelledCount: _cancelledCount,
                LastUpdatedAtUtc: _lastUpdatedAtUtc);
        }
    }

    private async Task ConsumerLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (SemanticQueueItem item in
                _channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                IncrementActive();
                try
                {
                    await ProcessAsync(item, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    DecrementActive();
                    PublishProgress();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Cancellation is expected; the loop exits.
        }
    }

    private async Task ProcessAsync(SemanticQueueItem item, CancellationToken cancellationToken)
    {
        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        LlmReviewResult result;
        try
        {
            result = await _reviewer.ReviewAsync(item.Request, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            IncrementCancelled();
            return;
        }
        catch (Exception)
        {
            IncrementFailed();
            return;
        }

        if (result.Classification == SemanticClassification.Unresolved)
        {
            if (!_lifetime.IsCurrent(item.CandidateId))
                return;
        }

        var persisted = new PersistedLlmReview(
            CandidateId: result.CandidateId,
            ScanId: item.ScanId,
            CacheKey: string.Empty,
            Classification: result.Classification,
            CategoryId: result.CategoryId?.Value ?? "SENS-001",
            Confidence: result.Confidence,
            ReasonCode: result.ReasonCode ?? "unresolved",
            InjectionDetected: result.InjectionDetected,
            PromptSha256: result.PromptSha256 ?? string.Empty,
            PromptVersion: result.PromptVersion ?? string.Empty,
            EndpointFingerprint: string.Empty,
            ModelFingerprint: string.Empty,
            AttemptedAtUtc: startedAt,
            Duration: DateTimeOffset.UtcNow - startedAt,
            Attempts: 1);

        try
        {
            await _persister.PersistAsync(persisted, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            IncrementCancelled();
            return;
        }

        IncrementCompleted();
    }

    private void IncrementActive()
    {
        lock (_gate) { _activeCount++; _lastUpdatedAtUtc = DateTimeOffset.UtcNow; }
    }

    private void DecrementActive()
    {
        lock (_gate) { _activeCount--; _lastUpdatedAtUtc = DateTimeOffset.UtcNow; }
    }

    private void IncrementCompleted()
    {
        lock (_gate) { _completedCount++; _lastUpdatedAtUtc = DateTimeOffset.UtcNow; }
    }

    private void IncrementFailed()
    {
        lock (_gate) { _failedCount++; _lastUpdatedAtUtc = DateTimeOffset.UtcNow; }
    }

    private void IncrementCancelled()
    {
        lock (_gate) { _cancelledCount++; _lastUpdatedAtUtc = DateTimeOffset.UtcNow; }
    }

    private void PublishProgress()
    {
        SemanticQueueProgress snapshot;
        lock (_gate)
        {
            snapshot = new SemanticQueueProgress(
                PendingCount: _channel.Reader.Count,
                ActiveCount: _activeCount,
                CompletedCount: _completedCount,
                FailedCount: _failedCount,
                CancelledCount: _cancelledCount,
                LastUpdatedAtUtc: _lastUpdatedAtUtc);
        }
        _progressSink.Publish(snapshot);
    }

    private static SemanticReviewQueueOptions NormalizeOptions(SemanticReviewQueueOptions input)
    {
        int capacity = input.Capacity <= 0
            ? SemanticReviewQueueOptions.FixedCapacity
            : Math.Min(SemanticReviewQueueOptions.FixedCapacity, input.Capacity);
        int consumers = input.MaxConsumerCount <= 0
            ? SemanticReviewQueueOptions.DefaultConsumers
            : Math.Clamp(input.MaxConsumerCount,
                SemanticReviewQueueOptions.MinConsumers,
                SemanticReviewQueueOptions.MaxConsumers);
        return new SemanticReviewQueueOptions
        {
            Capacity = capacity,
            MaxConsumerCount = consumers,
            ReviewDeadline = input.ReviewDeadline,
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Cancel(); } catch { /* best effort */ }
        _internalCts.Dispose();
    }
}
