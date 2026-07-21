namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Closed circuit state. Only three values exist; any state transition
/// must pass through one of these.
/// </summary>
public enum LlmCircuitState
{
    /// <summary>Closed — every request is admitted.</summary>
    Closed = 0,

    /// <summary>Open — every request is rejected.</summary>
    Open = 1,

    /// <summary>Half-open — at most one probe is admitted.</summary>
    HalfOpen = 2,
}

/// <summary>
/// Thread-safe circuit breaker for the approved LLM endpoint.
///
/// Counts only availability failures (HTTP 5xx, 429, request timeout,
/// network failure). Candidate / schema / client 4xx failures do not
/// count toward the threshold — they signal that the endpoint is
/// reachable and the request was rejected on its own merits, which
/// is a positive availability signal.
///
/// Transitions:
///   * Closed → Open after five consecutive availability failures.
///   * Open → HalfOpen after <see cref="OpenDuration"/> elapses.
///   * HalfOpen → Closed when the probe succeeds or yields a 4xx /
///     schema failure (treated as reachability confirmation).
///   * HalfOpen → Open when the probe fails with an availability
///     failure; the open window restarts.
/// </summary>
public sealed class LlmCircuitBreaker
{
    /// <summary>Default consecutive-failure threshold.</summary>
    public const int DefaultThreshold = 5;

    /// <summary>Default open duration before the first probe is allowed.</summary>
    public static readonly TimeSpan DefaultOpenDuration = TimeSpan.FromSeconds(60);

    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _clock;
    private readonly int _threshold;
    private readonly TimeSpan _openDuration;

    private int _consecutiveFailures;
    private DateTimeOffset? _openedAt;
    private bool _probeInFlight;

    public LlmCircuitBreaker(
        Func<DateTimeOffset>? clock = null,
        int threshold = DefaultThreshold,
        TimeSpan? openDuration = null)
    {
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        if (threshold < 1)
            throw new ArgumentOutOfRangeException(nameof(threshold),
                "Threshold must be at least 1.");
        _threshold = threshold;
        _openDuration = openDuration ?? DefaultOpenDuration;
    }

    /// <summary>Inspected state. Open may transition to HalfOpen lazily.</summary>
    public LlmCircuitState GetState()
    {
        lock (_gate)
        {
            if (_openedAt is null) return LlmCircuitState.Closed;
            if (_clock() - _openedAt.Value >= _openDuration)
                return LlmCircuitState.HalfOpen;
            return LlmCircuitState.Open;
        }
    }

    /// <summary>
    /// Attempts to admit one request. Returns <c>true</c> in the
    /// Closed state, <c>false</c> in the Open state, and <c>true</c>
    /// for exactly one probe in the HalfOpen state (subsequent calls
    /// are rejected until the probe outcome is recorded).
    /// </summary>
    public bool TryEnter()
    {
        lock (_gate)
        {
            if (_openedAt is null)
                return true;
            if (_clock() - _openedAt.Value < _openDuration)
                return false;
            // Half-open window. At most one probe at a time.
            if (_probeInFlight) return false;
            _probeInFlight = true;
            return true;
        }
    }

    /// <summary>
    /// Record a successful request. Resets the consecutive-failure
    /// counter and closes the circuit if it was open / half-open.
    /// </summary>
    public void RecordSuccess()
    {
        lock (_gate)
        {
            _consecutiveFailures = 0;
            _openedAt = null;
            _probeInFlight = false;
        }
    }

    /// <summary>
    /// Record an availability failure (5xx, 429, timeout, network).
    /// Bumps the consecutive counter, opens the circuit if the
    /// threshold is reached, and restarts the open window when the
    /// circuit is already open.
    /// </summary>
    public void RecordAvailabilityFailure()
    {
        lock (_gate)
        {
            _consecutiveFailures++;
            _probeInFlight = false;
            if (_openedAt is null)
            {
                if (_consecutiveFailures >= _threshold)
                {
                    _openedAt = _clock();
                }
            }
            else
            {
                // Already open (or half-open): restart the open window.
                _openedAt = _clock();
            }
        }
    }

    /// <summary>
    /// Record a non-availability failure (4xx, schema, parser
    /// mismatch). The endpoint is reachable, so the circuit is
    /// treated as reachable: the consecutive counter is reset and the
    /// circuit is closed. Any in-flight half-open probe is released.
    /// </summary>
    public void RecordClientOrSchemaFailure()
    {
        lock (_gate)
        {
            _consecutiveFailures = 0;
            _probeInFlight = false;
            _openedAt = null;
        }
    }
}
