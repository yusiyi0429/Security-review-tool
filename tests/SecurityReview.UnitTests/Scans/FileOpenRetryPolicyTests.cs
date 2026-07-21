using SecurityReview.Infrastructure.Windows;
using SecurityReview.Infrastructure.Windows.Files;

namespace SecurityReview.UnitTests.Scans;

public sealed class FileOpenRetryPolicyTests
{
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;
    private const int ErrorAccessDenied = 5;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorReparseTagMismatch = 4390;

    [Fact]
    public async Task Execute_retries_on_sharing_violation_at_100_then_300_then_900_ms_then_throws()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        int attempt = 0;
        List<FileOpenRetryEvent> events = [];
        var last = new WindowsSecurityException("CreateFileW", ErrorSharingViolation);

        await Assert.ThrowsAsync<WindowsSecurityException>(() =>
            policy.ExecuteAsync<int>(_ =>
            {
                attempt++;
                return Task.FromException<int>(last);
            }, events, CancellationToken.None));

        Assert.Equal(4, attempt);
        Assert.Equal(
            [TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(900)],
            delays);
        Assert.Equal(
            [
                new FileOpenRetryEvent(0, ErrorSharingViolation, 100),
                new FileOpenRetryEvent(1, ErrorSharingViolation, 300),
                new FileOpenRetryEvent(2, ErrorSharingViolation, 900),
            ],
            events);
    }

    [Fact]
    public async Task Execute_retries_on_lock_violation()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        int attempt = 0;

        await Assert.ThrowsAsync<WindowsSecurityException>(() =>
            policy.ExecuteAsync<int>(_ =>
            {
                attempt++;
                return Task.FromException<int>(new WindowsSecurityException("CreateFileW", ErrorLockViolation));
            }, [], CancellationToken.None));

        Assert.Equal(4, attempt);
        Assert.Equal(3, delays.Count);
    }

    [Fact]
    public async Task Execute_does_not_retry_on_access_denied()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        int attempt = 0;

        await Assert.ThrowsAsync<WindowsSecurityException>(() =>
            policy.ExecuteAsync<int>(_ =>
            {
                attempt++;
                return Task.FromException<int>(new WindowsSecurityException("CreateFileW", ErrorAccessDenied));
            }, [], CancellationToken.None));

        Assert.Equal(1, attempt);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task Execute_does_not_retry_on_file_not_found()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        int attempt = 0;

        await Assert.ThrowsAsync<WindowsSecurityException>(() =>
            policy.ExecuteAsync<int>(_ =>
            {
                attempt++;
                return Task.FromException<int>(new WindowsSecurityException("CreateFileW", ErrorFileNotFound));
            }, [], CancellationToken.None));

        Assert.Equal(1, attempt);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task Execute_does_not_retry_on_path_or_reparse_errors()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });

        foreach (int error in new[] { ErrorPathNotFound, ErrorReparseTagMismatch })
        {
            int attempt = 0;
            delays.Clear();
            await Assert.ThrowsAsync<WindowsSecurityException>(() =>
                policy.ExecuteAsync<int>(_ =>
                {
                    attempt++;
                    return Task.FromException<int>(new WindowsSecurityException("CreateFileW", error));
                }, [], CancellationToken.None));
            Assert.Equal(1, attempt);
            Assert.Empty(delays);
        }
    }

    [Fact]
    public async Task Execute_succeeds_on_retry_and_reports_events_only_for_failed_attempts()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        int attempt = 0;
        List<FileOpenRetryEvent> events = [];

        RetryOutcome<int> outcome = await policy.ExecuteAsync<int>(_ =>
        {
            attempt++;
            return attempt == 2
                ? Task.FromResult(42)
                : Task.FromException<int>(new WindowsSecurityException("CreateFileW", ErrorSharingViolation));
        }, events, CancellationToken.None);

        Assert.Equal(42, outcome.Value);
        Assert.True(outcome.Retried);
        Assert.Equal(2, attempt);
        Assert.Equal(
            [TimeSpan.FromMilliseconds(100)],
            delays);
        Assert.Equal(
            [
                new FileOpenRetryEvent(0, ErrorSharingViolation, 100),
            ],
            events);
    }

    [Fact]
    public async Task Execute_succeeds_on_initial_attempt_with_no_retry_events()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        List<FileOpenRetryEvent> events = [];

        RetryOutcome<int> outcome = await policy.ExecuteAsync<int>(_ => Task.FromResult(7), events,
            CancellationToken.None);

        Assert.Equal(7, outcome.Value);
        Assert.False(outcome.Retried);
        Assert.Empty(events);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task Execute_cancellation_propagates_immediately_and_skips_pending_delay()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, ct) =>
        {
            delays.Add(ts);
            return delays.Count switch { 1 => Task.Delay(Timeout.Infinite, ct), _ => Task.CompletedTask };
        });
        using var cts = new CancellationTokenSource();

        Task<RetryOutcome<int>> blocked = policy.ExecuteAsync<int>(_ =>
            throw new WindowsSecurityException("CreateFileW", ErrorSharingViolation), [], cts.Token);
        await Task.Yield();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocked);
        Assert.Single(delays);
    }

    [Fact]
    public async Task Retry_events_carry_only_attempt_error_code_and_delay()
    {
        List<TimeSpan> delays = [];
        var policy = new FileOpenRetryPolicy(delay: (ts, _) => { delays.Add(ts); return Task.CompletedTask; });
        List<FileOpenRetryEvent> events = [];

        await Assert.ThrowsAsync<WindowsSecurityException>(() =>
            policy.ExecuteAsync<int>(_ =>
                throw new WindowsSecurityException("CreateFileW", ErrorSharingViolation),
                events, CancellationToken.None));

        Assert.All(events, e =>
        {
            string[] props = ["Attempt", "ErrorCode", "DelayMs"];
            Assert.Equal(props.Length, typeof(FileOpenRetryEvent).GetProperties().Length);
        });
    }
}
