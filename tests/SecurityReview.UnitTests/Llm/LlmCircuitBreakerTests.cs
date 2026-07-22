using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.UnitTests.Llm;

/// <summary>
/// Tests for <see cref="LlmCircuitBreaker"/>: five consecutive
/// availability failures open the circuit, 60s later one half-open
/// probe is admitted, and the probe outcome decides whether the
/// circuit reopens or closes. Candidate / schema / client 4xx
/// failures are not counted as availability failures.
/// </summary>
public sealed class LlmCircuitBreakerTests
{
    private sealed class MockClock
    {
        public DateTimeOffset UtcNow { get; set; } =
            new DateTimeOffset(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);
        public DateTimeOffset Read() => UtcNow;
    }

    private static LlmCircuitBreaker Build(MockClock clock, int threshold = 5, int openSeconds = 60) =>
        new(clock: clock.Read, threshold: threshold, openDuration: TimeSpan.FromSeconds(openSeconds));

    [Fact]
    public void Closed_by_default()
    {
        var cb = Build(new MockClock());
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Opens_after_five_consecutive_availability_failures()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Open, cb.GetState());
    }

    [Fact]
    public void Stays_closed_after_four_availability_failures()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 4; i++)
            cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Does_not_count_4xx_or_schema_failures()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 25; i++)
            cb.RecordClientOrSchemaFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Client_errors_reset_consecutive_availability_failure_count()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 4; i++)
        {
            cb.RecordAvailabilityFailure();
            cb.RecordClientOrSchemaFailure();
        }
        // Each client error proves reachability and resets the consecutive count.
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
        cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Success_resets_consecutive_availability_count()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 4; i++)
            cb.RecordAvailabilityFailure();
        cb.RecordSuccess();
        for (int i = 0; i < 4; i++)
            cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Success_after_four_failures_then_single_5xx_keeps_closed()
    {
        var cb = Build(new MockClock());
        for (int i = 0; i < 4; i++)
            cb.RecordAvailabilityFailure();
        cb.RecordSuccess();
        cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Transitions_to_half_open_after_open_duration()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Open, cb.GetState());

        clock.UtcNow = clock.UtcNow.AddSeconds(59);
        Assert.Equal(LlmCircuitState.Open, cb.GetState());

        clock.UtcNow = clock.UtcNow.AddSeconds(2);
        Assert.Equal(LlmCircuitState.HalfOpen, cb.GetState());
    }

    [Fact]
    public void TryEnter_returns_false_when_open()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        Assert.False(cb.TryEnter());
    }

    [Fact]
    public void TryEnter_admits_exactly_one_half_open_probe()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        clock.UtcNow = clock.UtcNow.AddSeconds(61);

        Assert.True(cb.TryEnter());
        Assert.False(cb.TryEnter());
        Assert.False(cb.TryEnter());
    }

    [Fact]
    public void Probe_success_closes_circuit()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        clock.UtcNow = clock.UtcNow.AddSeconds(61);

        Assert.True(cb.TryEnter());
        cb.RecordSuccess();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());

        // Subsequent calls are admitted immediately.
        for (int i = 0; i < 5; i++)
            Assert.True(cb.TryEnter());
    }

    [Fact]
    public void Probe_availability_failure_reopens_for_another_full_window()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        clock.UtcNow = clock.UtcNow.AddSeconds(61);

        Assert.True(cb.TryEnter());
        cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Open, cb.GetState());
        Assert.False(cb.TryEnter());

        clock.UtcNow = clock.UtcNow.AddSeconds(61);
        Assert.True(cb.TryEnter());
    }

    [Fact]
    public void Probe_4xx_does_not_reopen()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        clock.UtcNow = clock.UtcNow.AddSeconds(61);

        Assert.True(cb.TryEnter());
        cb.RecordClientOrSchemaFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
    }

    [Fact]
    public void Probe_4xx_releases_in_flight_slot()
    {
        var clock = new MockClock();
        var cb = Build(clock);
        for (int i = 0; i < 5; i++)
            cb.RecordAvailabilityFailure();
        clock.UtcNow = clock.UtcNow.AddSeconds(61);

        Assert.True(cb.TryEnter());
        cb.RecordClientOrSchemaFailure();
        // After the probe completes (even with 4xx), the next call is admitted.
        Assert.True(cb.TryEnter());
    }

    [Fact]
    public void Threshold_of_three_works_when_configured()
    {
        var cb = Build(new MockClock(), threshold: 3);
        cb.RecordAvailabilityFailure();
        cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Closed, cb.GetState());
        cb.RecordAvailabilityFailure();
        Assert.Equal(LlmCircuitState.Open, cb.GetState());
    }
}
