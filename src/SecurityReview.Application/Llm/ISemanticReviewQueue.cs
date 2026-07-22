using SecurityReview.Domain;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Bounded queue for semantic-review candidates. The queue owns a
/// single <see cref="System.Threading.Channels.Channel{T}"/> of fixed
/// capacity and a configurable number of consumer tasks (2–4). Each
/// consumer drains one <see cref="SemanticQueueItem"/> at a time,
/// invokes the configured <see cref="ISemanticReviewer"/>, and
/// persists the result through <see cref="ISemanticReviewPersister"/>
/// when the candidate remains current.
///
/// Contracts:
///   * <c>RequiresSemanticReview=false</c> items are never enqueued
///     (the writer receives a <c>false</c> return value).
///   * Cancellation stops new writes immediately, cancels in-flight
///     HTTP requests, and persists Unresolved results only when the
///     candidate is still current.
///   * Progress is counts and status flags only — never candidate id,
///     value, context, or model / endpoint identifiers.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Naming", "CA1711", Justification = "Domain noun is 'queue'; renaming would obscure the semantic-review flow.")]
public interface ISemanticReviewQueue
{
    /// <summary>
    /// Attempt to enqueue one item. Returns <c>false</c> if
    /// <see cref="SemanticQueueItem.RequiresSemanticReview"/> is
    /// <c>false</c>, if the channel is full, or if cancellation has
    /// already been requested.
    /// </summary>
    ValueTask<bool> EnqueueAsync(SemanticQueueItem item, CancellationToken cancellationToken);

    /// <summary>
    /// Mark the queue as no longer accepting writes. Already-enqueued
    /// items continue to be processed.
    /// </summary>
    void CompleteAdding();

    /// <summary>
    /// Run consumer tasks until the channel is drained and all
    /// in-flight reviews have completed (or been cancelled).
    /// </summary>
    Task RunAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Cancel writes immediately and cancel in-flight HTTP requests.
    /// Unresolved results are persisted only when the candidate is
    /// still current.
    /// </summary>
    void Cancel();

    /// <summary>Configured maximum number of consumer tasks (2–4).</summary>
    int MaxConsumers { get; }

    /// <summary>Configured channel capacity.</summary>
    int Capacity { get; }

    /// <summary>Number of items currently waiting in the channel.</summary>
    int PendingCount { get; }

    /// <summary>Snapshot of progress counters (no candidate identity).</summary>
    SemanticQueueProgress GetProgress();
}

/// <summary>
/// One enqueued semantic-review candidate. Carries the input request
/// the consumer will hand to the <see cref="ISemanticReviewer"/>, the
/// scan id used for persistence, the active rule-pack hash, and the
/// adapter version that produced the request envelope. The
/// <see cref="RequiresSemanticReview"/> flag is the queue's
/// precondition: items where it is <c>false</c> are rejected.
/// </summary>
public sealed record SemanticQueueItem(
    CandidateId CandidateId,
    ScanId ScanId,
    SemanticReviewRequest Request,
    bool RequiresSemanticReview,
    string RulePackHash,
    string AdapterVersion);

/// <summary>Counts-only progress snapshot.</summary>
public sealed record SemanticQueueProgress(
    int PendingCount,
    int ActiveCount,
    int CompletedCount,
    int FailedCount,
    int CancelledCount,
    int UnresolvedCount,
    DateTimeOffset LastUpdatedAtUtc);

/// <summary>
/// Optional configuration for <see cref="SemanticReviewQueue"/>.
/// <see cref="MaxConsumers"/> is clamped to [2, 4].
/// <see cref="Capacity"/> is fixed at 1000.
/// </summary>
public sealed class SemanticReviewQueueOptions
{
    /// <summary>Hard ceiling on channel capacity.</summary>
    public const int FixedCapacity = 1000;

    /// <summary>Minimum number of consumers.</summary>
    public const int MinConsumers = 2;

    /// <summary>Maximum number of consumers.</summary>
    public const int MaxConsumers = 4;

    /// <summary>Default number of consumers.</summary>
    public const int DefaultConsumers = 2;

    public int Capacity { get; init; } = FixedCapacity;
    public int MaxConsumerCount { get; init; } = DefaultConsumers;
    public TimeSpan ReviewDeadline { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// Provides the lifetime predicate used when deciding whether to
/// persist an Unresolved result. Implementations are typically backed
/// by the active scan / candidate store.
/// </summary>
public interface ISemanticCandidateLifetime
{
    /// <summary>
    /// Returns <c>true</c> when the candidate is still relevant
    /// (e.g. the scan is still running and the candidate has not been
    /// superseded). Cancellation must propagate through the supplied
    /// token.
    /// </summary>
    bool IsCurrent(CandidateId candidateId);
}

/// <summary>
/// Persistence seam for completed semantic reviews. The
/// implementation decides whether the encrypted payload carries a
/// rationale, an Unresolved reason code, or both.
/// </summary>
public interface ISemanticReviewPersister
{
    Task PersistAsync(PersistedLlmReview review, CancellationToken cancellationToken);
}

/// <summary>
/// Stable, non-PII record of one semantic review attempt. Endpoint
/// host, model id, candidate value, and context never appear.
/// </summary>
public sealed record PersistedLlmReview(
    CandidateId CandidateId,
    ScanId ScanId,
    string CacheKey,
    SemanticClassification Classification,
    string CategoryId,
    double? Confidence,
    string ReasonCode,
    bool InjectionDetected,
    string PromptSha256,
    string PromptVersion,
    string EndpointFingerprint,
    string ModelFingerprint,
    DateTimeOffset AttemptedAtUtc,
    TimeSpan Duration,
    int Attempts);

/// <summary>
/// Sink for <see cref="SemanticQueueProgress"/>. P5 ships a no-op
/// default; P6 wires the persistent sink. The contract is closed —
/// implementations receive counts and a UTC timestamp only.
/// </summary>
public interface ISemanticReviewProgressSink
{
    void Publish(SemanticQueueProgress progress);
}

/// <summary>
/// Composition-root default that drops every progress event. P6
/// replaces this with a persistent implementation.
/// </summary>
public sealed class NullSemanticReviewProgressSink : ISemanticReviewProgressSink
{
    public void Publish(SemanticQueueProgress progress) { _ = progress; }
}
