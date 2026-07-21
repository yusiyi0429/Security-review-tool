using System.ComponentModel;
using System.Windows.Input;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for <see cref="AsyncRelayCommand"/>: concurrent execution
/// prevention, IsRunning, re-enable after exception/cancel, error sink,
/// cancellation support, and no .Result/.Wait blocking.
/// </summary>
public sealed class AsyncRelayCommandTests
{
    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<ErrorEntry> Errors { get; } = new();

        public void Report(string code, string message)
        {
            Errors.Add(new ErrorEntry(code, message));
        }
    }

    private sealed record ErrorEntry(string Code, string Message);

    // ------------------------------------------------------------------
    // Concurrent execution prevention
    // ------------------------------------------------------------------

    [Fact]
    public async Task Prevents_concurrent_execution_by_default()
    {
        var tcs = new TaskCompletionSource();
        int executions = 0;
        var cmd = new AsyncRelayCommand(async _ =>
        {
            Interlocked.Increment(ref executions);
            await tcs.Task;
        }, new TestErrorSink());

        var firstTask = cmd.ExecuteAsync(null);
        // Second call while first is running — should be dropped
        var secondTask = cmd.ExecuteAsync(null);

        await Task.Delay(50);
        Assert.Equal(1, executions);
        Assert.True(cmd.IsRunning);

        tcs.SetResult();
        await firstTask;
        Assert.False(cmd.IsRunning);
    }

    [Fact]
    public async Task Allows_concurrent_execution_when_configured()
    {
        int maxConcurrent = 0;
        int current = 0;
        var tcs = new TaskCompletionSource();

        var cmd = new AsyncRelayCommand(async _ =>
        {
            int now = Interlocked.Increment(ref current);
            Interlocked.CompareExchange(ref maxConcurrent, now, now);
            if (now > maxConcurrent) Interlocked.Exchange(ref maxConcurrent, now);

            await Task.Delay(50);
            Interlocked.Decrement(ref current);
        }, new TestErrorSink(), allowConcurrent: true);

        var tasks = new List<Task>();
        for (int i = 0; i < 5; i++)
            tasks.Add(cmd.ExecuteAsync(null));

        await Task.WhenAll(tasks);
        Assert.True(maxConcurrent > 1);
    }

    // ------------------------------------------------------------------
    // IsRunning
    // ------------------------------------------------------------------

    [Fact]
    public async Task IsRunning_reflects_execution_state()
    {
        var tcs = new TaskCompletionSource();
        var cmd = new AsyncRelayCommand(async _ =>
        {
            await tcs.Task;
        }, new TestErrorSink());

        Assert.False(cmd.IsRunning);

        var task = cmd.ExecuteAsync(null);
        await Task.Delay(50);
        Assert.True(cmd.IsRunning);

        tcs.SetResult();
        await task;
        Assert.False(cmd.IsRunning);
    }

    // ------------------------------------------------------------------
    // Re-enable after exception
    // ------------------------------------------------------------------

    [Fact]
    public async Task Reenables_after_exception()
    {
        var sink = new TestErrorSink();
        var cmd = new AsyncRelayCommand(new Func<object?, Task>(_ =>
        {
            throw new InvalidOperationException("test failure");
        }), sink);

        await cmd.ExecuteAsync(null);
        Assert.False(cmd.IsRunning);
        Assert.NotEmpty(sink.Errors);
        Assert.Contains(sink.Errors, e => e.Code == "command_error");

        // Should be executable again
        bool canExec = ((ICommand)cmd).CanExecute(null);
        Assert.True(canExec);
    }

    [Fact]
    public async Task Reenables_after_cancellation()
    {
        var cmd = new AsyncRelayCommand(async (_, ct) =>
        {
            await Task.Delay(5000, ct);
        }, new TestErrorSink());

        var task = cmd.ExecuteAsync(null);
        cmd.Cancel();
        await task;

        Assert.False(cmd.IsRunning);
        Assert.True(((ICommand)cmd).CanExecute(null));
    }

    // ------------------------------------------------------------------
    // Error sink receives typed codes
    // ------------------------------------------------------------------

    [Fact]
    public async Task Error_sink_receives_typed_codes()
    {
        var sink = new TestErrorSink();
        var cmd = new AsyncRelayCommand(new Func<object?, Task>(_ =>
        {
            throw new InvalidOperationException("test-error");
        }), sink);

        await cmd.ExecuteAsync(null);

        Assert.NotEmpty(sink.Errors);
        var error = sink.Errors[0];
        Assert.False(string.IsNullOrEmpty(error.Code));
        Assert.Equal("command_error", error.Code);
        Assert.DoesNotContain("at SecurityReview", error.Message);
    }

    [Fact]
    public async Task Cancellation_does_not_report_error()
    {
        var sink = new TestErrorSink();
        var cmd = new AsyncRelayCommand(async (_, ct) =>
        {
            await Task.Delay(100, ct);
        }, sink);

        cmd.Cancel();
        await cmd.ExecuteAsync(null);
        Assert.Empty(sink.Errors);
    }

    // ------------------------------------------------------------------
    // No .Result/.Wait blocking
    // ------------------------------------------------------------------

    [Fact]
    public async Task Execution_never_blocks_calling_thread()
    {
        var cmd = new AsyncRelayCommand(async _ =>
        {
            await Task.Delay(50);
        }, new TestErrorSink());

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var task = cmd.ExecuteAsync(null);
        await task.WaitAsync(cts.Token);
        Assert.False(cmd.IsRunning);
    }

    // ------------------------------------------------------------------
    // PropertyChanged raised
    // ------------------------------------------------------------------

    [Fact]
    public async Task PropertyChanged_fires_for_IsRunning()
    {
        var tcs = new TaskCompletionSource();
        var sink = new TestErrorSink();
        int changedCount = 0;
        var cmd = new AsyncRelayCommand(async _ =>
        {
            await Task.Delay(20);
        }, sink);

        cmd.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AsyncRelayCommand.IsRunning))
                Interlocked.Increment(ref changedCount);
        };

        await cmd.ExecuteAsync(null);
        // IsRunning toggles true → false, so at least 2 changes
        Assert.True(changedCount >= 2,
            $"Expected >= 2 PropertyChanged events for IsRunning; got {changedCount}");
    }

    // ------------------------------------------------------------------
    // Cancellation support
    // ------------------------------------------------------------------

    [Fact]
    public async Task Cancel_stops_execution()
    {
        bool completedNormally = true;
        var cmd = new AsyncRelayCommand(async (_, ct) =>
        {
            try
            {
                await Task.Delay(5000, ct);
            }
            catch (OperationCanceledException)
            {
                completedNormally = false;
                throw;
            }
        }, new TestErrorSink());

        var task = cmd.ExecuteAsync(null);
        await Task.Delay(50);
        cmd.Cancel();
        await task;

        Assert.False(cmd.IsRunning);
        Assert.False(completedNormally);
    }

    [Fact]
    public async Task CanExecute_returns_false_while_running()
    {
        var tcs = new TaskCompletionSource();
        var cmd = new AsyncRelayCommand(async _ =>
        {
            await tcs.Task;
        }, new TestErrorSink());

        Assert.True(((ICommand)cmd).CanExecute(null));

        var task = cmd.ExecuteAsync(null);
        await Task.Delay(50);
        Assert.False(((ICommand)cmd).CanExecute(null));

        tcs.SetResult();
        await task;
        Assert.True(((ICommand)cmd).CanExecute(null));
    }

    // ------------------------------------------------------------------
    // Parameterized execute
    // ------------------------------------------------------------------

    [Fact]
    public async Task Parameterized_execute_receives_parameter()
    {
        object? received = null;
        var cmd = new AsyncRelayCommand(async param =>
        {
            received = param;
            await Task.CompletedTask;
        }, new TestErrorSink());

        await cmd.ExecuteAsync("hello");
        Assert.Equal("hello", received);
    }

    // ------------------------------------------------------------------
    // CanExecute delegate
    // ------------------------------------------------------------------

    [Fact]
    public void CanExecute_uses_supplied_predicate()
    {
        var sink = new TestErrorSink();
        var cmd = new AsyncRelayCommand(
            _ => Task.CompletedTask,
            canExecute: _ => false,
            errorSink: sink);

        Assert.False(((ICommand)cmd).CanExecute(null));
    }

    // ------------------------------------------------------------------
    // INotifyPropertyChanged
    // ------------------------------------------------------------------

    [Fact]
    public void Implements_INotifyPropertyChanged()
    {
        var cmd = new AsyncRelayCommand(_ => Task.CompletedTask, new TestErrorSink());
        Assert.IsAssignableFrom<INotifyPropertyChanged>(cmd);
    }

    // ------------------------------------------------------------------
    // RaiseCanExecuteChanged
    // ------------------------------------------------------------------

    [Fact]
    public void RaiseCanExecuteChanged_fires_CanExecuteChanged()
    {
        var cmd = new AsyncRelayCommand(_ => Task.CompletedTask, new TestErrorSink());
        bool fired = false;

        ((ICommand)cmd).CanExecuteChanged += (_, _) => fired = true;
        cmd.RaiseCanExecuteChanged();
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // Dispose cancels pending execution
    // ------------------------------------------------------------------

    [Fact]
    public async Task Dispose_cancels_pending()
    {
        var cmd = new AsyncRelayCommand(async (_, ct) =>
        {
            await Task.Delay(5000, ct);
        }, new TestErrorSink());

        var task = cmd.ExecuteAsync(null);
        cmd.Dispose();
        await task;

        Assert.False(cmd.IsRunning);
    }
}
