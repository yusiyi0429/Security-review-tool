using SecurityReview.Infrastructure.Windows;

namespace SecurityReview.Infrastructure.Windows.Files;

// Bounded retry policy for transient file-open failures. Only sharing and
// lock violations retry (initial attempt plus three retries at 100/300/900 ms);
// other errors (access denied, not found, path invalid, reparse, etc.)
// fail closed on the first attempt. Retry events expose attempt number, error
// code, and delay only — never path or file name.
public sealed record FileOpenRetryEvent(int Attempt, int ErrorCode, int DelayMs)
{
    public const int ErrorSharingViolation = 32;
    public const int ErrorLockViolation = 33;
}

public sealed record RetryOutcome<T>(T Value, bool Retried, IReadOnlyList<FileOpenRetryEvent> Events);

public sealed class FileOpenRetryPolicy
{
    public static readonly IReadOnlyList<int> DefaultDelaysMilliseconds = new[] { 100, 300, 900 };

    public FileOpenRetryPolicy(IReadOnlyList<int>? delaysMilliseconds = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        DelaysMilliseconds = delaysMilliseconds ?? DefaultDelaysMilliseconds;
        Delay = delay ?? ((span, cancellationToken) => Task.Delay(span, cancellationToken));
    }

    public IReadOnlyList<int> DelaysMilliseconds { get; }
    public Func<TimeSpan, CancellationToken, Task> Delay { get; }

    public static bool IsRetryable(long errorCode) =>
        errorCode == (long)FileOpenRetryEvent.ErrorSharingViolation
        || errorCode == (long)FileOpenRetryEvent.ErrorLockViolation;

    public async Task<RetryOutcome<T>> ExecuteAsync<T>(
        Func<CancellationToken, Task<T>> attempt,
        List<FileOpenRetryEvent>? eventLog = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        var events = eventLog ?? new List<FileOpenRetryEvent>();
        WindowsSecurityException? initialFailure = null;

        try
        {
            T initial = await attempt(cancellationToken).ConfigureAwait(false);
            return new RetryOutcome<T>(initial, Retried: false, events);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WindowsSecurityException ex) when (!IsRetryable(ex.ErrorCode))
        {
            throw;
        }
        catch (WindowsSecurityException ex)
        {
            initialFailure = ex;
        }

        WindowsSecurityException last = initialFailure
            ?? throw new InvalidOperationException(
                "Retry loop entered without a retryable initial failure.");

        for (int attemptIndex = 0; attemptIndex < DelaysMilliseconds.Count; attemptIndex++)
        {
            int delayMs = DelaysMilliseconds[attemptIndex];
            events.Add(new FileOpenRetryEvent(attemptIndex, (int)last.ErrorCode, delayMs));

            await Delay(TimeSpan.FromMilliseconds(delayMs), cancellationToken)
                .ConfigureAwait(false);

            try
            {
                T result = await attempt(cancellationToken).ConfigureAwait(false);
                return new RetryOutcome<T>(result, Retried: true, events);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (WindowsSecurityException ex) when (!IsRetryable(ex.ErrorCode))
            {
                throw;
            }
            catch (WindowsSecurityException ex)
            {
                last = ex;
            }
        }

        throw last;
    }
}
