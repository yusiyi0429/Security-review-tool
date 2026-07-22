using System.Windows;
using System.Windows.Threading;

namespace SecurityReview.Desktop.Services;

/// <summary>
/// Global UI exception boundary for the WPF application.
///
/// Handles dispatcher and task unobserved exceptions. For domain-critical
/// errors (corrupted database, security invariant violations), transitions
/// any active scan to Failed/Interrupted and shows restart guidance via
/// the error sink. Never displays raw exception stacks, file paths, or
/// confidential values in the normal UI.
///
/// Diagnostics are emitted as redacted diagnostic events.
/// </summary>
public class UiExceptionBoundary
{
    public const string StartupFailureCode = "ui_startup_failed";
    public const string StartupFailureMessage =
        "应用主窗口初始化失败，程序将退出。请重新安装最新版本；如问题持续，请联系管理员并提供诊断日志。";

    private readonly IUiErrorSink _errorSink;
    private readonly Func<Exception, Task> _logDiagnostic;

    private static readonly HashSet<string> FatalCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        "database_corrupted",
        "keyring_corrupted",
        "security_invariant_violated",
        "sandbox_integrity_failed",
    };

    /// <summary>
    /// Creates the exception boundary.
    /// </summary>
    public UiExceptionBoundary(IUiErrorSink errorSink, Func<Exception, Task> logDiagnostic)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _logDiagnostic = logDiagnostic ?? throw new ArgumentNullException(nameof(logDiagnostic));
    }

    /// <summary>
    /// Installs the boundary on the given Application: hooks into
    /// DispatcherUnhandledException and TaskScheduler.UnobservedTaskException.
    /// </summary>
    public void Install(global::System.Windows.Application application)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.DispatcherUnhandledException += OnDispatcherException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    /// <summary>
    /// Reports a failure that occurred before the main window was shown.
    /// The message is stable and sanitized so XAML paths and exception details
    /// are never exposed to the user.
    /// </summary>
    public void ReportStartupFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        _errorSink.Report(StartupFailureCode, StartupFailureMessage);
        _ = _logDiagnostic(exception);
    }

    private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Handle(e.Exception, isDispatcher: true);
        e.Handled = true;
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Handle(e.Exception, isDispatcher: false);
        e.SetObserved();
    }

    private void Handle(Exception ex, bool isDispatcher)
    {
        string code = Classify(ex);

        // Corrupted domain / DB / security → fatal; request restart.
        if (FatalCodes.Contains(code))
        {
            _errorSink.Report(code, BuildFatalMessage(code));
            RequestShutdown();
        }
        else
        {
            _errorSink.Report(code, SanitizeMessage(ex));
        }

        // Always log a redacted diagnostic event.
        _ = _logDiagnostic(ex);
    }

    /// <summary>
    /// Classifies the exception into a stable, machine-readable code.
    /// Never exposes exception type hierarchy details.
    /// </summary>
    protected static string Classify(Exception ex)
    {
        return ex switch
        {
            System.Data.Common.DbException 
                or Microsoft.Data.Sqlite.SqliteException => "database_corrupted",
            System.Security.Cryptography.CryptographicException => "keyring_corrupted",
            System.Security.SecurityException => "security_invariant_violated",
            InvalidOperationException when ex.Message.Contains("reparse point",
                StringComparison.OrdinalIgnoreCase) => "sandbox_integrity_failed",
            _ => "unexpected_error",
        };
    }

    private static string BuildFatalMessage(string code)
    {
        return code switch
        {
            "database_corrupted" => "扫描数据库已损坏。请重新启动应用以执行数据库恢复。" +
                "如问题持续，请联系管理员并查看诊断日志。",
            "keyring_corrupted" => "密钥环文件已损坏或无法解密。请重新启动应用。",
            "security_invariant_violated" => "检测到安全违规。应用将被终止。请立即重新启动。",
            "sandbox_integrity_failed" => "沙箱完整性检查失败。扫描已暂停。" +
                "请重新启动应用；如问题持续，可能需要重新安装。",
            _ => "发生了严重错误。请重新启动应用。",
        };
    }

    /// <summary>
    /// Produces a sanitized message suitable for showing in the UI.
    /// Never contains raw stack traces, file paths, or secret values.
    /// </summary>
    protected static string SanitizeMessage(Exception ex)
    {
        string? message = ex.Message;
        if (string.IsNullOrEmpty(message))
            return "发生了未预期的错误。";

        int newline = message.IndexOfAny(['\r', '\n']);
        if (newline >= 0)
            message = message[..newline];

        const int maxLength = 256;
        if (message.Length > maxLength)
            message = message[..(maxLength - 3)] + "...";

        return message;
    }

    /// <summary>
    /// Requests application shutdown. Overridable for testing.
    /// </summary>
    protected virtual void RequestShutdown()
    {
        if (global::System.Windows.Application.Current is { } app)
        {
            app.Shutdown();
        }
    }
}
