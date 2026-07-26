using System.Threading.Channels;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;

namespace SecurityReview.IntegrationTests.Llm;

/// <summary>
/// Integration tests for <see cref="SemanticReviewQueue"/>:
///   * Candidates with <c>RequiresSemanticReview=false</c> are never
///     enqueued.
///   * Channel capacity is 1000; further writes are rejected.
///   * Consumer count is bounded 2–4 from options.
///   * Cancellation stops new writes, cancels in-flight work, and
///     persists unresolved results only when the candidate is still
///     current.
///   * <see cref="ISemanticReviewQueue.GetProgress"/> reports counts
///     and status only — never a candidate id or context.
/// </summary>
public sealed class SemanticReviewQueueTests
{
    private static SemanticReviewRequest BuildRequest() =>
        new(
            CandidateId: new CandidateId(Guid.NewGuid()),
            CategoryHint: CategoryId.Parse("SENS-001"),
            ContentKind: "text",
            Extension: ".txt",
            VirtualPath: "docs/notes.txt",
            FullContext: "irrelevant",
            CandidateValue: "candidate",
            CandidateLocator: new SourceLocator.TextLocator(1, 1, 0, 9),
            DeterministicSecrets: Array.Empty<DeterministicSecretSpan>());

    private static SemanticQueueItem BuildItem(bool requiresReview, CandidateId? candidateId = null)
    {
        var request = BuildRequest();
        return new SemanticQueueItem(
            CandidateId: candidateId ?? request.CandidateId,
            ScanId: new ScanId(Guid.NewGuid()),
            Request: request,
            RequiresSemanticReview: requiresReview,
            RulePackHash: new string('a', 64),
            AdapterVersion: "1.0.0");
    }

    // ---------- RequiresSemanticReview precondition ----------

    [Fact]
    public async Task EnqueueAsync_returns_false_when_requires_semantic_review_is_false()
    {
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            new RecordingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        using var cts = new CancellationTokenSource();

        bool accepted = await queue.EnqueueAsync(BuildItem(requiresReview: false), cts.Token);

        Assert.False(accepted);
        Assert.Equal(0, queue.PendingCount);
    }

    [Fact]
    public async Task EnqueueAsync_returns_true_when_requires_semantic_review_is_true()
    {
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            new RecordingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        using var cts = new CancellationTokenSource();

        bool accepted = await queue.EnqueueAsync(BuildItem(requiresReview: true), cts.Token);

        Assert.True(accepted);
        Assert.Equal(1, queue.PendingCount);
    }

    // ---------- Channel capacity ----------

    [Fact]
    public async Task Capacity_is_1000_and_overflow_rejects_writes()
    {
        // Replace the channel model directly via internal API so we can
        // saturate without spinning up reviewers.
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions { Capacity = 1000 },
            new BlockingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());

        for (int i = 0; i < 1000; i++)
            Assert.True(await queue.EnqueueAsync(BuildItem(requiresReview: true), default));

        // 1001st must be rejected (channel is full and we did not start
        // any consumers).
        bool accepted = await queue.EnqueueAsync(BuildItem(requiresReview: true), default);
        Assert.False(accepted);
    }

    // ---------- Consumer count ----------

    [Fact]
    public async Task MaxConsumers_defaults_to_2_and_is_capped_at_4()
    {
        var reviewer = new CountingReviewer(delay: TimeSpan.FromMilliseconds(50));
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());

        // Enqueue a few items then start; the queue should run at most
        // 2 in parallel by default.
        for (int i = 0; i < 8; i++)
            await queue.EnqueueAsync(BuildItem(requiresReview: true), default);

        queue.CompleteAdding();
        await queue.RunAsync(default);

        Assert.True(reviewer.MaxConcurrentObserved >= 2,
            $"Expected ≥2 concurrent consumers, observed {reviewer.MaxConcurrentObserved}");
        Assert.True(reviewer.MaxConcurrentObserved <= 4,
            $"Expected ≤4 concurrent consumers (default cap), observed {reviewer.MaxConcurrentObserved}");
        Assert.Equal(2, queue.MaxConsumers);
    }

    [Fact]
    public async Task MaxConsumers_clamps_to_4_even_when_configured_higher()
    {
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions { MaxConsumerCount = 99 },
            new RecordingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        Assert.Equal(4, queue.MaxConsumers);
    }

    [Fact]
    public async Task MaxConsumers_clamps_to_minimum_2_when_configured_lower()
    {
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions { MaxConsumerCount = 1 },
            new RecordingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        Assert.Equal(2, queue.MaxConsumers);
    }

    // ---------- Cancellation ----------

    [Fact]
    public async Task Cancel_stops_new_writes_and_rejects_subsequent_enqueue()
    {
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            new RecordingReviewer(),
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        queue.Cancel();

        Assert.False(await queue.EnqueueAsync(BuildItem(requiresReview: true), default));
    }

    [Fact]
    public async Task Cancel_cancels_in_flight_http_via_cancellation_token()
    {
        var reviewStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var reviewer = new CountingReviewer(
            delay: TimeSpan.FromSeconds(5),
            beforeReview: (_, _) => reviewStarted.TrySetResult());
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            new NoopLifetime(),
            new NoopRepository(),
            new RecordingProgressSink());
        var item = BuildItem(requiresReview: true);
        await queue.EnqueueAsync(item, default);

        queue.CompleteAdding();
        Task run = queue.RunAsync(default);
        await reviewStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        queue.Cancel();

        // The already-running reviewer observes cancellation through
        // its Task.Delay throw.
        await run;

        Assert.True(reviewer.CancellationObserved);
    }

    // ---------- Persist unresolved only if candidate remains current ----------

    [Fact]
    public async Task Unresolved_result_is_persisted_when_candidate_remains_current()
    {
        var item = BuildItem(requiresReview: true);
        var reviewer = new FixedResultReviewer(LlmReviewResult_Unresolved(item.CandidateId));
        var lifetime = new StubLifetime(isCurrent: true);
        var repo = new RecordingRepository();
        var sink = new RecordingProgressSink();

        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            lifetime,
            repo,
            sink);
        await queue.EnqueueAsync(item, default);
        queue.CompleteAdding();
        await queue.RunAsync(default);

        Assert.Single(repo.Persisted);
        Assert.Equal(item.CandidateId, repo.Persisted[0].CandidateId);
    }

    [Fact]
    public async Task Unresolved_result_is_not_persisted_when_candidate_no_longer_current()
    {
        var item = BuildItem(requiresReview: true);
        var reviewer = new FixedResultReviewer(LlmReviewResult_Unresolved(item.CandidateId));
        var lifetime = new StubLifetime(isCurrent: false);
        var repo = new RecordingRepository();
        var sink = new RecordingProgressSink();

        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            lifetime,
            repo,
            sink);
        await queue.EnqueueAsync(item, default);
        queue.CompleteAdding();
        await queue.RunAsync(default);

        Assert.Empty(repo.Persisted);
    }

    [Fact]
    public async Task Confirmed_or_possible_result_is_always_persisted_even_when_no_longer_current()
    {
        var item = BuildItem(requiresReview: true);
        var reviewer = new FixedResultReviewer(LlmReviewResult_Confirmed(item.CandidateId));
        var lifetime = new StubLifetime(isCurrent: false);
        var repo = new RecordingRepository();

        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            lifetime,
            repo,
            new RecordingProgressSink());
        await queue.EnqueueAsync(item, default);
        queue.CompleteAdding();
        await queue.RunAsync(default);

        Assert.Single(repo.Persisted);
        Assert.Equal(item.CandidateId, repo.Persisted[0].CandidateId);
    }

    [Fact]
    public async Task Persistence_failure_is_reported_without_aborting_the_queue()
    {
        var item = BuildItem(requiresReview: true);
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            new FixedResultReviewer(LlmReviewResult_Confirmed(item.CandidateId)),
            new NoopLifetime(),
            new ThrowingRepository(),
            new RecordingProgressSink());
        await queue.EnqueueAsync(item, default);
        queue.CompleteAdding();

        await queue.RunAsync(default);

        SemanticQueueProgress progress = queue.GetProgress();
        Assert.Equal(1, progress.FailedCount);
        Assert.Equal(0, progress.CompletedCount);
    }

    // ---------- Progress ----------

    [Fact]
    public async Task Progress_reports_counts_only_never_candidate_identity()
    {
        var reviewer = new FixedResultReviewer(LlmReviewResult_Confirmed(new CandidateId(Guid.NewGuid())));
        var sink = new RecordingProgressSink();
        var queue = new SemanticReviewQueue(
            new SemanticReviewQueueOptions(),
            reviewer,
            new StubLifetime(isCurrent: true),
            new RecordingRepository(),
            sink);

        SemanticQueueItem item = BuildItem(requiresReview: true);
        await queue.EnqueueAsync(item, default);
        queue.CompleteAdding();
        await queue.RunAsync(default);

        SemanticQueueProgress progress = queue.GetProgress();
        Assert.Equal(0, progress.PendingCount);
        Assert.Equal(0, progress.ActiveCount);
        Assert.True(progress.CompletedCount + progress.CancelledCount >= 1);
        Assert.True(progress.LastUpdatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(-5));
        Assert.DoesNotContain(item.CandidateId.Value.ToString(),
            progress.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    // ---------- Test fixtures ----------

    private static LlmReviewResult LlmReviewResult_Unresolved(CandidateId id) => new()
    {
        CandidateId = id,
        Classification = SemanticClassification.Unresolved,
        CategoryId = CategoryId.Parse("SENS-001"),
        Confidence = null,
        Rationale = string.Empty,
        ReasonCode = "test_unresolved",
        InjectionDetected = false,
        PromptSha256 = "deadbeef",
        PromptVersion = "semantic-review-v1",
    };

    private static LlmReviewResult LlmReviewResult_Confirmed(CandidateId id) => new()
    {
        CandidateId = id,
        Classification = SemanticClassification.Confirmed,
        CategoryId = CategoryId.Parse("SENS-002"),
        Confidence = 0.9,
        Rationale = "ok",
        ReasonCode = null,
        InjectionDetected = false,
        PromptSha256 = "deadbeef",
        PromptVersion = "semantic-review-v1",
    };

    private sealed class RecordingReviewer : ISemanticReviewer
    {
        public Task<LlmReviewResult> ReviewAsync(SemanticReviewRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(LlmReviewResult_Confirmed(request.CandidateId));
    }

    private sealed class BlockingReviewer : ISemanticReviewer
    {
        public async Task<LlmReviewResult> ReviewAsync(SemanticReviewRequest request, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class CountingReviewer : ISemanticReviewer
    {
        private readonly TimeSpan _delay;
        private readonly Action<SemanticReviewRequest, CancellationToken>? _beforeReview;
        private int _inFlight;
        private int _observed;
        private readonly object _gate = new();

        public CountingReviewer(TimeSpan delay, Action<SemanticReviewRequest, CancellationToken>? beforeReview = null)
        {
            _delay = delay;
            _beforeReview = beforeReview;
        }

        public int MaxConcurrentObserved
        {
            get { lock (_gate) return _observed; }
        }

        public bool CancellationObserved { get; private set; }

        public async Task<LlmReviewResult> ReviewAsync(SemanticReviewRequest request, CancellationToken cancellationToken = default)
        {
            lock (_gate)
            {
                _inFlight++;
                if (_inFlight > _observed) _observed = _inFlight;
            }
            _beforeReview?.Invoke(request, cancellationToken);
            try
            {
                await Task.Delay(_delay, cancellationToken).ConfigureAwait(false);
                return LlmReviewResult_Confirmed(request.CandidateId);
            }
            catch (OperationCanceledException)
            {
                CancellationObserved = true;
                throw;
            }
            finally
            {
                lock (_gate) _inFlight--;
            }
        }
    }

    private sealed class FixedResultReviewer : ISemanticReviewer
    {
        private readonly LlmReviewResult _result;
        public FixedResultReviewer(LlmReviewResult result) => _result = result;
        public Task<LlmReviewResult> ReviewAsync(SemanticReviewRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(_result);
    }

    private sealed class NoopLifetime : ISemanticCandidateLifetime
    {
        public bool IsCurrent(CandidateId candidateId) => true;
    }

    private sealed class StubLifetime : ISemanticCandidateLifetime
    {
        private readonly bool _isCurrent;
        public StubLifetime(bool isCurrent) => _isCurrent = isCurrent;
        public bool IsCurrent(CandidateId candidateId) => _isCurrent;
    }

    private sealed class NoopRepository : ISemanticReviewPersister
    {
        public Task PersistAsync(PersistedLlmReview review, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class RecordingRepository : ISemanticReviewPersister
    {
        public List<PersistedLlmReview> Persisted { get; } = new();
        public Task PersistAsync(PersistedLlmReview review, CancellationToken cancellationToken)
        {
            Persisted.Add(review);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingRepository : ISemanticReviewPersister
    {
        public Task PersistAsync(
            PersistedLlmReview review,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("simulated persistence failure");
    }

    private sealed class RecordingProgressSink : ISemanticReviewProgressSink
    {
        public List<SemanticQueueProgress> Updates { get; } = new();
        public void Publish(SemanticQueueProgress progress) => Updates.Add(progress);
    }
}
