namespace SecurityReview.Application.Llm;

/// <summary>
/// Fail-closed semantic queue used when no LLM reviewer is configured.
/// Deterministic findings are preserved, while candidates that require
/// semantic review are rejected so the orchestrator records an unresolved gap.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Naming",
    "CA1711",
    Justification = "The domain contract is explicitly named semantic review queue.")]
public sealed class UnavailableSemanticReviewQueue : ISemanticReviewQueue
{
    public int MaxConsumers => 0;

    public int Capacity => 0;

    public int PendingCount => 0;

    public ValueTask<bool> EnqueueAsync(
        SemanticQueueItem item,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);
        _ = cancellationToken;
        return ValueTask.FromResult(false);
    }

    public void CompleteAdding()
    {
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public void Cancel()
    {
    }

    public SemanticQueueProgress GetProgress() =>
        new(
            PendingCount: 0,
            ActiveCount: 0,
            CompletedCount: 0,
            FailedCount: 0,
            CancelledCount: 0,
            UnresolvedCount: 0,
            LastUpdatedAtUtc: DateTimeOffset.UtcNow);
}
