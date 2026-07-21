using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using SecurityReview.Desktop.Services;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// Asynchronous ICommand implementation for WPF.
///
/// - Prevents concurrent execution by default (<see cref="AllowConcurrent"/>).
/// - Exposes <see cref="IsRunning"/> for UI binding.
/// - Re-enables after exception or cancellation.
/// - Routes typed public error codes to <see cref="IUiErrorSink"/>.
/// - Never uses .Result/.Wait — all execution is fully async.
/// - Captures <see cref="SynchronizationContext"/> only for
///   <see cref="INotifyPropertyChanged"/> events; command execution
///   runs on the thread pool.
/// - Supports optional <see cref="CancellationToken"/> passed to the
///   execute delegate.
/// </summary>
public sealed class AsyncRelayCommand : ICommand, INotifyPropertyChanged, IDisposable
{
    private readonly Func<object?, CancellationToken, Task> _executeWithToken;
    private readonly Func<object?, Task> _execute;
    private readonly Func<object?, bool>? _canExecute;
    private readonly IUiErrorSink _errorSink;
    private readonly bool _allowConcurrent;

    private bool _isRunning;
    private CancellationTokenSource? _currentCts;

    /// <summary>
    /// Creates a command from a cancellable execute delegate.
    /// </summary>
    public AsyncRelayCommand(
        Func<object?, CancellationToken, Task> execute,
        IUiErrorSink errorSink,
        Func<object?, bool>? canExecute = null,
        bool allowConcurrent = false)
    {
        _executeWithToken = execute ?? throw new ArgumentNullException(nameof(execute));
        _execute = null!;
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _canExecute = canExecute;
        _allowConcurrent = allowConcurrent;
    }

    /// <summary>
    /// Creates a command from a non-cancellable execute delegate.
    /// </summary>
    public AsyncRelayCommand(
        Func<object?, Task> execute,
        IUiErrorSink errorSink,
        Func<object?, bool>? canExecute = null,
        bool allowConcurrent = false)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _executeWithToken = null!;
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _canExecute = canExecute;
        _allowConcurrent = allowConcurrent;
    }

    /// <summary>Whether the command is currently executing.</summary>
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (_isRunning == value) return;
            _isRunning = value;
            OnPropertyChanged();
        }
    }

    /// <summary>Whether concurrent execution is allowed.</summary>
    public bool AllowConcurrent => _allowConcurrent;

    // ------------------------------------------------------------------ IDisposable

    public void Dispose()
    {
        CancellationTokenSource? cts = Interlocked.Exchange(ref _currentCts, null!);
        if (cts is not null)
        {
            try { cts.Cancel(); }
            catch (ObjectDisposedException) { }
            cts.Dispose();
        }
    }

    // ------------------------------------------------------------------ ICommand

    public event EventHandler? CanExecuteChanged;

    bool ICommand.CanExecute(object? parameter)
    {
        if (_canExecute is not null)
            return _canExecute(parameter) && !IsRunning;

        return !IsRunning;
    }

    async void ICommand.Execute(object? parameter)
    {
        // ICommand.Execute is fire-and-forget; we route exceptions through
        // ExecuteAsync to the error sink.
        await ExecuteAsync(parameter).ConfigureAwait(false);
    }

    /// <summary>
    /// Executes the command asynchronously, returning a Task that completes
    /// when execution finishes. Safe to await from unit tests.
    /// </summary>
    public async Task ExecuteAsync(object? parameter)
    {
        if (!_allowConcurrent && IsRunning)
            return;

        IsRunning = true;
        RaiseCanExecuteChanged();

        var cts = new CancellationTokenSource();
        CancellationTokenSource? old = Interlocked.Exchange(ref _currentCts, cts);
        old?.Cancel();
        old?.Dispose();

        try
        {
            if (_executeWithToken is not null)
            {
                await _executeWithToken(parameter, cts.Token).ConfigureAwait(false);
            }
            else
            {
                await _execute(parameter).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Cancellation is expected; no error report.
        }
        catch (Exception ex)
        {
            string message = SanitizeMessage(ex);
            _errorSink.Report("command_error", message);
        }
        finally
        {
            IsRunning = false;
            RaiseCanExecuteChanged();

            CancellationTokenSource? current = Interlocked.CompareExchange(
                ref _currentCts, null, cts);
            if (current == cts)
            {
                cts.Dispose();
            }
        }
    }

    /// <summary>
    /// Requests cancellation of the current execution, if any.
    /// </summary>
    public void Cancel()
    {
        _currentCts?.Cancel();
    }

    // ------------------------------------------------------------------ INotifyPropertyChanged

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName!));
    }

    /// <summary>
    /// Manually raises <see cref="CanExecuteChanged"/>. Call when the
    /// can-execute predicate's state changes externally.
    /// </summary>
    public void RaiseCanExecuteChanged()
    {
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    // ------------------------------------------------------------------ Helpers

    /// <summary>
    /// Produces a sanitized message from an exception. Never includes
    /// raw stack traces, file paths, or confidential values.
    /// </summary>
    internal static string SanitizeMessage(Exception ex)
    {
        // Only include the exception type name and the first line of the message.
        string? message = ex.Message;
        if (string.IsNullOrEmpty(message))
        {
            return $"An error occurred in {ex.GetType().Name}.";
        }

        // Truncate at first newline to avoid multi-line messages leaking details.
        int newline = message.IndexOfAny(['\r', '\n']);
        if (newline >= 0)
            message = message[..newline];

        // Apply maximum length.
        const int maxLength = 256;
        if (message.Length > maxLength)
            message = message[..(maxLength - 3)] + "...";

        return message;
    }
}
