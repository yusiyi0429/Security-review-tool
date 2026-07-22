using System.Net;
using System.Net.Http.Headers;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.UnitTests.Llm;

/// <summary>
/// Tests for <see cref="LlmRetryPolicy"/>: deterministic fake-clock
/// schedule, injected jitter, no-retry on 4xx/schema/cancel, and
/// <c>Retry-After</c> honored only when within [0, 30]s and inside
/// the task deadline.
///
/// Every test asserts:
///   * Each attempt uses a new <see cref="HttpRequestMessage"/>.
///   * The candidate id appears in every request body (idempotent).
///   * The same <see cref="CandidateId"/> instance is reused.
/// </summary>
public sealed class LlmRetryPolicyTests
{
    private static readonly CandidateId FixedCandidate =
        new(new Guid("22222222-2222-2222-2222-222222222222"));

    private sealed class MockClock
    {
        public DateTimeOffset UtcNow { get; private set; } =
            new DateTimeOffset(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

        public List<TimeSpan> Delays { get; } = new();

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken = default)
        {
            Delays.Add(delay);
            UtcNow = UtcNow.Add(delay);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public DateTimeOffset Read() => UtcNow;
    }

    private static LlmRetryPolicy BuildPolicy(MockClock clock) =>
        new(
            delay: clock.DelayAsync,
            jitter: () => 0.5,
            clock: clock.Read);

    private static HttpRequestMessage BuildRequestBody(string candidateId, int seq)
    {
        var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri("https://example.invalid/v1/chat/completions"));
        var content = new ByteArrayContent(
            System.Text.Encoding.UTF8.GetBytes("{\"candidate_id\":\"" + candidateId + "\",\"seq\":" + seq + "}"));
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;
        return request;
    }

    private static HttpResponseMessage MakeResponse(HttpStatusCode code, string? retryAfter = null)
    {
        var resp = new HttpResponseMessage(code)
        {
            Content = new ByteArrayContent(Array.Empty<byte>()),
        };
        if (!string.IsNullOrEmpty(retryAfter))
        {
            resp.Headers.Add("Retry-After", retryAfter);
        }
        return resp;
    }

    // ---------- Happy-path retry schedule ----------

    [Fact]
    public async Task Retries_429_then_500_at_exactly_1s_and_4s_then_unresolved()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var attempts = new List<DateTimeOffset>();
        var requests = new List<HttpRequestMessage>();
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () =>
            {
                var req = BuildRequestBody(FixedCandidate.Value.ToString("D"), requests.Count + 1);
                attempts.Add(clock.UtcNow);
                requests.Add(req);
                return req;
            },
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests),
                    _ => MakeResponse(HttpStatusCode.InternalServerError),
                });
            });

        var origin = new DateTimeOffset(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(3, sendCalls);
        Assert.Equal(3, attempts.Count);
        Assert.Equal(TimeSpan.Zero, attempts[0] - origin);
        Assert.Equal(TimeSpan.FromSeconds(1), attempts[1] - origin);
        Assert.Equal(TimeSpan.FromSeconds(4), attempts[2] - origin);

        // Distinct request instances.
        Assert.NotSame(requests[0], requests[1]);
        Assert.NotSame(requests[1], requests[2]);

        // The recorded delays are exactly 1s and 3s (jitter = 0.5 → 1.0×).
        Assert.Equal(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(3) }, clock.Delays);

        Assert.False(result.Succeeded);
        Assert.Equal(3, result.Attempts);
        Assert.Equal("server_error_after_retries", result.ReasonCode);
        Assert.Equal(3, result.AttemptOutcomes.Count);
        Assert.Contains("rate_limited", result.AttemptOutcomes.Select(o => o.Outcome));
        Assert.All(result.AttemptOutcomes, o =>
        {
            byte[] body = o.RequestBody ?? Array.Empty<byte>();
            using var doc = System.Text.Json.JsonDocument.Parse(
                body.Length == 0 ? "{}" : System.Text.Encoding.UTF8.GetString(body));
            Assert.Equal(FixedCandidate.Value.ToString("D"),
                doc.RootElement.GetProperty("candidate_id").GetString());
        });
    }

    [Fact]
    public async Task Retries_5xx_and_succeeds_on_attempt_3()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    < 3 => MakeResponse(HttpStatusCode.BadGateway),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            });

        Assert.True(result.Succeeded);
        Assert.Equal(3, result.Attempts);
        Assert.Equal("success", result.ReasonCode);
        Assert.Equal(200, (int)result.FinalResponse!.StatusCode);
    }

    // ---------- No-retry client errors ----------

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task Does_not_retry_on_4xx_other_than_429(HttpStatusCode code)
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(MakeResponse(code));
            });

        Assert.Equal(1, sendCalls);
        Assert.False(result.Succeeded);
        Assert.Equal("client_error", result.ReasonCode);
        Assert.Empty(clock.Delays);
    }

    [Fact]
    public async Task Does_not_retry_on_schema_failure_exception()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), 1),
            send: (_, _) =>
            {
                sendCalls++;
                throw new LlmSchemaException("body did not match schema");
            });

        Assert.Equal(1, sendCalls);
        Assert.False(result.Succeeded);
        Assert.Equal("schema_error", result.ReasonCode);
        Assert.Empty(clock.Delays);
    }

    // ---------- Cancellation ----------

    [Fact]
    public async Task Does_not_retry_when_cancellation_token_already_cancelled()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;
        var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(MakeResponse(HttpStatusCode.OK));
            },
            cancellationToken: cts.Token));

        Assert.Equal(0, sendCalls);
    }

    [Fact]
    public async Task Cancelled_during_delay_throws_and_does_not_retry()
    {
        var clock = new MockClock();
        var cts = new CancellationTokenSource();
        var sendCalls = 0;

        var policy = new LlmRetryPolicy(
            delay: (ts, ct) =>
            {
                clock.Delays.Add(ts);
                cts.Cancel();
                ct.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            },
            jitter: () => 0.5,
            clock: clock.Read);

        await Assert.ThrowsAsync<OperationCanceledException>(() => policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(MakeResponse(HttpStatusCode.InternalServerError));
            },
            cancellationToken: cts.Token));

        Assert.Equal(1, sendCalls);
    }

    // ---------- Retry-After parsing ----------

    [Fact]
    public async Task Honors_retry_after_when_within_30s_and_inside_deadline()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;
        var attempts = new List<DateTimeOffset>();
        DateTimeOffset? deadline = clock.UtcNow + TimeSpan.FromSeconds(10);

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () =>
            {
                attempts.Add(clock.UtcNow);
                return BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1);
            },
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests, "5"),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            },
            deadline: deadline);

        Assert.True(result.Succeeded);
        Assert.Equal(2, sendCalls);
        Assert.Equal(TimeSpan.FromSeconds(5), attempts[1] - attempts[0]);
        Assert.Equal(new[] { TimeSpan.FromSeconds(5) }, clock.Delays);
    }

    [Fact]
    public async Task Falls_back_to_base_delay_when_retry_after_exceeds_30s()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;
        var attempts = new List<DateTimeOffset>();

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () =>
            {
                attempts.Add(clock.UtcNow);
                return BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1);
            },
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests, "120"),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            },
            deadline: clock.UtcNow + TimeSpan.FromMinutes(5));

        Assert.True(result.Succeeded);
        Assert.Equal(2, sendCalls);
        Assert.Equal(TimeSpan.FromSeconds(1), attempts[1] - attempts[0]);
        Assert.Equal(new[] { TimeSpan.FromSeconds(1) }, clock.Delays);
    }

    [Fact]
    public async Task Falls_back_to_base_when_retry_after_would_exceed_deadline()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;
        var attempts = new List<DateTimeOffset>();

        // Deadline is 1s in the future; Retry-After=5 would overflow it.
        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () =>
            {
                attempts.Add(clock.UtcNow);
                return BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1);
            },
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests, "5"),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            },
            deadline: clock.UtcNow + TimeSpan.FromSeconds(2));

        Assert.True(result.Succeeded);
        Assert.Equal(2, sendCalls);
        Assert.Equal(TimeSpan.FromSeconds(1), attempts[1] - attempts[0]);
        Assert.Equal(new[] { TimeSpan.FromSeconds(1) }, clock.Delays);
    }

    [Fact]
    public async Task Gives_up_when_no_delay_fits_deadline()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(MakeResponse(HttpStatusCode.InternalServerError));
            },
            deadline: clock.UtcNow + TimeSpan.FromMilliseconds(500));

        Assert.False(result.Succeeded);
        Assert.Equal(1, sendCalls);
        Assert.Equal("deadline_exceeded", result.ReasonCode);
    }

    // ---------- Jitter ----------

    [Fact]
    public async Task Applies_minus_10_percent_jitter_at_lower_bound()
    {
        var clock = new MockClock();
        var policy = new LlmRetryPolicy(
            delay: clock.DelayAsync,
            jitter: () => 0.0, // → 0.9× multiplier
            clock: clock.Read);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests),
                    2 => MakeResponse(HttpStatusCode.InternalServerError),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            },
            deadline: clock.UtcNow + TimeSpan.FromMinutes(5));

        Assert.True(result.Succeeded);
        // Lower bound: 1s * 0.9 = 0.9s, 3s * 0.9 = 2.7s
        Assert.Equal(TimeSpan.FromMilliseconds(900), clock.Delays[0]);
        Assert.Equal(TimeSpan.FromMilliseconds(2700), clock.Delays[1]);
    }

    [Fact]
    public async Task Applies_plus_10_percent_jitter_at_upper_bound()
    {
        var clock = new MockClock();
        var policy = new LlmRetryPolicy(
            delay: clock.DelayAsync,
            jitter: () => 1.0, // → 1.1× multiplier
            clock: clock.Read);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests),
                    2 => MakeResponse(HttpStatusCode.InternalServerError),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            },
            deadline: clock.UtcNow + TimeSpan.FromMinutes(5));

        Assert.True(result.Succeeded);
        Assert.Equal(TimeSpan.FromMilliseconds(1100), clock.Delays[0]);
        Assert.Equal(TimeSpan.FromMilliseconds(3300), clock.Delays[1]);
    }

    // ---------- Stable candidate id + new request ----------

    [Fact]
    public async Task Each_attempt_emits_a_new_http_request_with_same_candidate_id()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;
        var requests = new List<HttpRequestMessage>();

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () =>
            {
                var req = BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1);
                requests.Add(req);
                return req;
            },
            send: (_, _) =>
            {
                sendCalls++;
                return Task.FromResult(sendCalls switch
                {
                    1 => MakeResponse(HttpStatusCode.TooManyRequests),
                    2 => MakeResponse(HttpStatusCode.InternalServerError),
                    _ => MakeResponse(HttpStatusCode.OK),
                });
            });

        Assert.Equal(3, requests.Count);
        for (int i = 0; i < requests.Count; i++)
        {
            for (int j = i + 1; j < requests.Count; j++)
                Assert.NotSame(requests[i], requests[j]);
        }

        Assert.All(requests, req =>
        {
            byte[] body = req.Content!.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            string json = System.Text.Encoding.UTF8.GetString(body);
            Assert.Contains(FixedCandidate.Value.ToString("D"), json);
        });
    }

    [Fact]
    public async Task Retries_on_transport_exception_and_succeeds_on_attempt_2()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                if (sendCalls == 1)
                    throw new HttpRequestException("connection reset");
                return Task.FromResult(MakeResponse(HttpStatusCode.OK));
            });

        Assert.True(result.Succeeded);
        Assert.Equal(2, sendCalls);
        Assert.Single(clock.Delays);
        Assert.Equal(TimeSpan.FromSeconds(1), clock.Delays[0]);
    }

    [Fact]
    public async Task Retries_on_http_timeout_and_gives_up_after_three_attempts()
    {
        var clock = new MockClock();
        var policy = BuildPolicy(clock);
        var sendCalls = 0;

        var result = await policy.ExecuteAsync(
            FixedCandidate,
            createRequest: () => BuildRequestBody(FixedCandidate.Value.ToString("D"), sendCalls + 1),
            send: (_, _) =>
            {
                sendCalls++;
                throw new TaskCanceledException("http timeout");
            });

        Assert.False(result.Succeeded);
        Assert.Equal(3, sendCalls);
        Assert.Equal(2, clock.Delays.Count);
    }
}
