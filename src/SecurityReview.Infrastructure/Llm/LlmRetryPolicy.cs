using System.Globalization;
using System.Net;
using SecurityReview.Domain;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Resilience policy for the semantic-review LLM call: a single
/// <see cref="CandidateId"/> is retried up to three times total on
/// transient availability failures (HTTP 5xx, HTTP 429, request
/// timeout, network failure). Client / schema failures (4xx other
/// than 429, schema mismatch, <see cref="LlmSchemaException"/>) are
/// never retried. <c>Retry-After</c> is honored only when the parsed
/// value lies in <c>[0, 30]s</c> AND still fits inside the supplied
/// task deadline; otherwise the policy falls back to the base delay.
///
/// Each attempt produces a fresh <see cref="HttpRequestMessage"/> via
/// the supplied factory — the candidate id is preserved across
/// attempts so the wire payload is idempotent.
///
/// Delay computation is deterministic given an injected jitter
/// function. Production wires <c>() =&gt; RandomNumberGenerator
/// .GetInt32(0, 10_000) / 10_000.0</c> for cryptographic seeding;
/// tests inject a fixed function.
/// </summary>
public sealed class LlmRetryPolicy
{
    /// <summary>Maximum total attempts (initial + retries).</summary>
    public const int DefaultMaxAttempts = 3;

    /// <summary>Base delay before the second attempt.</summary>
    public static readonly TimeSpan FirstBaseDelay = TimeSpan.FromSeconds(1);

    /// <summary>Base delay before the third (final) attempt.</summary>
    public static readonly TimeSpan SecondBaseDelay = TimeSpan.FromSeconds(3);

    /// <summary>Upper bound for any <c>Retry-After</c> we honor.</summary>
    public static readonly TimeSpan MaxRetryAfterWindow = TimeSpan.FromSeconds(30);

    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Func<double> _jitter;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TimeSpan _firstDelay;
    private readonly TimeSpan _secondDelay;
    private readonly TimeSpan _maxRetryAfter;
    private int _maxAttempts;

    public LlmRetryPolicy(
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        Func<double>? jitter = null,
        Func<DateTimeOffset>? clock = null,
        TimeSpan? firstDelay = null,
        TimeSpan? secondDelay = null,
        TimeSpan? maxRetryAfter = null,
        int maxAttempts = DefaultMaxAttempts)
    {
        _delay = delay ?? DefaultDelay;
        _jitter = jitter ?? DefaultJitter;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _firstDelay = firstDelay ?? FirstBaseDelay;
        _secondDelay = secondDelay ?? SecondBaseDelay;
        _maxRetryAfter = maxRetryAfter ?? MaxRetryAfterWindow;
        if (maxAttempts < 1)
            throw new ArgumentOutOfRangeException(nameof(maxAttempts),
                "Max attempts must be at least 1.");
        _maxAttempts = maxAttempts;
    }

    /// <summary>
    /// Run the supplied <paramref name="send"/> delegate under retry
    /// rules. Each attempt constructs a fresh request via
    /// <paramref name="createRequest"/>. The <paramref name="candidateId"/>
    /// is exposed so callers can stamp the request body, log
    /// correlation, and assert idempotency.
    /// </summary>
    public async Task<LlmRetryResult> ExecuteAsync(
        CandidateId candidateId,
        Func<HttpRequestMessage> createRequest,
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send,
        DateTimeOffset? deadline = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(createRequest);
        ArgumentNullException.ThrowIfNull(send);

        var requests = new List<HttpRequestMessage>();
        var outcomes = new List<LlmAttemptOutcome>();
        HttpResponseMessage? lastResponse = null;

        int attempts = 0;
        TimeSpan? pendingRetryAfter = null;

        while (attempts < _maxAttempts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (attempts > 0)
            {
                TimeSpan delay = ComputeDelay(attempts, pendingRetryAfter, deadline);
                if (delay == TimeSpan.Zero)
                {
                    // No delay fits inside the deadline → bail out.
                    return LlmRetryResult.Failure(
                        attempts, requests, outcomes, lastResponse, "deadline_exceeded");
                }
                await _delay(delay, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }

            HttpRequestMessage request = createRequest();
            requests.Add(request);

            DateTimeOffset startedAt = _clock();
            HttpResponseMessage response;
            int? statusCode = null;
            string outcomeName;

            try
            {
                response = await send(request, cancellationToken).ConfigureAwait(false);
            }
            catch (LlmSchemaException ex)
            {
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, _clock() - startedAt,
                    null, "schema_error", SnapshotBody(request), ex.Message));
                return LlmRetryResult.Failure(
                    attempts + 1, requests, outcomes, null, "schema_error");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (TaskCanceledException)
            {
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, _clock() - startedAt,
                    null, "timeout", SnapshotBody(request), null));
                pendingRetryAfter = null;
                attempts++;
                continue;
            }
            catch (HttpRequestException ex)
            {
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, _clock() - startedAt,
                    null, "transport_error", SnapshotBody(request), ex.Message));
                pendingRetryAfter = null;
                attempts++;
                continue;
            }

            lastResponse = response;
            statusCode = (int)response.StatusCode;
            TimeSpan duration = _clock() - startedAt;

            if (statusCode is >= 200 and < 300)
            {
                outcomeName = "success";
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, duration, statusCode, outcomeName,
                    SnapshotBody(request), null));
                return LlmRetryResult.Success(attempts + 1, requests, outcomes, response);
            }

            if (IsClientError(statusCode.Value))
            {
                outcomeName = "client_error";
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, duration, statusCode, outcomeName,
                    SnapshotBody(request), null));
                return LlmRetryResult.Failure(
                    attempts + 1, requests, outcomes, response, "client_error");
            }

            if (statusCode == (int)HttpStatusCode.TooManyRequests)
            {
                outcomeName = "rate_limited";
                pendingRetryAfter = ParseRetryAfter(response);
                outcomes.Add(new LlmAttemptOutcome(
                    attempts + 1, startedAt, duration, statusCode, outcomeName,
                    SnapshotBody(request), null));
                attempts++;
                continue;
            }

            outcomeName = "server_error";
            pendingRetryAfter = null;
            outcomes.Add(new LlmAttemptOutcome(
                attempts + 1, startedAt, duration, statusCode, outcomeName,
                SnapshotBody(request), null));
            attempts++;
        }

        LlmAttemptOutcome? last = outcomes.LastOrDefault();
        string finalReason = last is null
            ? "transport_error_after_retries"
            : last.Outcome switch
            {
                "timeout" => "timeout_after_retries",
                "transport_error" => "transport_error_after_retries",
                "server_error" => "server_error_after_retries",
                "rate_limited" => "rate_limited_after_retries",
                _ => "transport_error_after_retries",
            };
        return LlmRetryResult.Failure(_maxAttempts, requests, outcomes, lastResponse, finalReason);
    }

    private TimeSpan ComputeDelay(int completedAttempts, TimeSpan? retryAfter, DateTimeOffset? deadline)
    {
        TimeSpan baseDelay = completedAttempts == 1 ? _firstDelay : _secondDelay;
        TimeSpan candidate = baseDelay;

        if (retryAfter.HasValue)
        {
            TimeSpan raw = retryAfter.Value;
            if (raw >= TimeSpan.Zero && raw <= _maxRetryAfter)
            {
                if (!deadline.HasValue || _clock() + raw <= deadline.Value)
                {
                    candidate = raw;
                }
            }
        }

        double jitterValue = _jitter();
        if (jitterValue < 0.0) jitterValue = 0.0;
        if (jitterValue > 1.0) jitterValue = 1.0;
        double multiplier = 1.0 + (jitterValue - 0.5) * 0.2;
        long ticks = (long)(candidate.Ticks * multiplier);
        if (ticks < 0) ticks = 0;
        return TimeSpan.FromTicks(ticks);
    }

    private TimeSpan? ParseRetryAfter(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Retry-After", out IEnumerable<string>? values))
            return null;
        string? raw = values.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        if (int.TryParse(raw.Trim(), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out int seconds))
        {
            return TimeSpan.FromSeconds(Math.Max(0, seconds));
        }

        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset when))
        {
            TimeSpan diff = when - _clock();
            return diff > TimeSpan.Zero ? diff : TimeSpan.Zero;
        }

        return null;
    }

    private static bool IsClientError(int status) =>
        status is >= 400 and < 500 && status != 429;

    private static byte[] SnapshotBody(HttpRequestMessage request)
    {
        try
        {
            return request.Content is null
                ? Array.Empty<byte>()
                : request.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    private static Task DefaultDelay(TimeSpan delay, CancellationToken cancellationToken)
        => Task.Delay(delay, cancellationToken);

    private static double DefaultJitter()
        => Random.Shared.NextDouble();
}

/// <summary>
/// Result of one <see cref="LlmRetryPolicy.ExecuteAsync"/> call. The
/// caller owns the lifecycle of <see cref="FinalResponse"/> and the
/// per-attempt <see cref="HttpRequestMessage"/> instances in
/// <see cref="Requests"/>.
/// </summary>
public sealed class LlmRetryResult
{
    public bool Succeeded { get; }
    public int Attempts { get; }
    public IReadOnlyList<HttpRequestMessage> Requests { get; }
    public IReadOnlyList<LlmAttemptOutcome> AttemptOutcomes { get; }
    public HttpResponseMessage? FinalResponse { get; }
    public string ReasonCode { get; }

    private LlmRetryResult(
        bool succeeded,
        int attempts,
        IReadOnlyList<HttpRequestMessage> requests,
        IReadOnlyList<LlmAttemptOutcome> attemptOutcomes,
        HttpResponseMessage? finalResponse,
        string reasonCode)
    {
        Succeeded = succeeded;
        Attempts = attempts;
        Requests = requests;
        AttemptOutcomes = attemptOutcomes;
        FinalResponse = finalResponse;
        ReasonCode = reasonCode;
    }

    internal static LlmRetryResult Success(
        int attempts,
        IReadOnlyList<HttpRequestMessage> requests,
        IReadOnlyList<LlmAttemptOutcome> outcomes,
        HttpResponseMessage response)
        => new(true, attempts, requests, outcomes, response, "success");

    internal static LlmRetryResult Failure(
        int attempts,
        IReadOnlyList<HttpRequestMessage> requests,
        IReadOnlyList<LlmAttemptOutcome> outcomes,
        HttpResponseMessage? finalResponse,
        string reasonCode)
        => new(false, attempts, requests, outcomes, finalResponse, reasonCode);
}

/// <summary>
/// One attempt's outcome captured by the retry policy.
/// </summary>
public sealed record LlmAttemptOutcome(
    int AttemptNumber,
    DateTimeOffset StartedAtUtc,
    TimeSpan Duration,
    int? StatusCode,
    string Outcome,
    byte[]? RequestBody,
    string? ErrorDetail);

/// <summary>
/// Thrown from the per-attempt <c>send</c> delegate when the response
/// body is structurally invalid (failed the closed parser). The retry
/// policy treats this as terminal — no retry is attempted.
/// </summary>
public sealed class LlmSchemaException : Exception
{
    public LlmSchemaException(string message) : base(message) { }
    public LlmSchemaException(string message, Exception inner) : base(message, inner) { }
}
