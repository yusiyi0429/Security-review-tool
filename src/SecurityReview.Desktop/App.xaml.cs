using System.IO;
using System.Windows;
using System.Windows.Markup;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop;

/// <summary>
/// WPF application entry point. Builds the manual composition root,
/// installs the global UI exception boundary, and opens the main shell
/// with health-blocked semantics when keyring/DB/sandbox is unavailable.
/// </summary>
public partial class App : global::System.Windows.Application, IDisposable
{
    private CompositionRoot? _root;
    private bool _disposed;

    public App()
    {
        EnsureWindowsDirectoryEnvironment();
    }

    internal static void EnsureWindowsDirectoryEnvironment()
    {
        if (!string.IsNullOrWhiteSpace(
                Environment.GetEnvironmentVariable("windir", EnvironmentVariableTarget.Process)))
        {
            return;
        }

        string? windowsDirectory = Environment.GetEnvironmentVariable(
            "SystemRoot", EnvironmentVariableTarget.Process);
        if (string.IsNullOrWhiteSpace(windowsDirectory))
        {
            windowsDirectory = Path.GetDirectoryName(Environment.SystemDirectory);
        }

        if (!string.IsNullOrWhiteSpace(windowsDirectory) &&
            Path.IsPathFullyQualified(windowsDirectory))
        {
            Environment.SetEnvironmentVariable(
                "windir", windowsDirectory, EnvironmentVariableTarget.Process);
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Build the composition root with production paths.
        _root = new CompositionRoot(CompositionRoot.Args.ForProduction());

        // Install the global UI exception boundary.
        var boundary = new UiExceptionBoundary(
            _root.ErrorSink,
            ex =>
            {
                Exception cause = ex;
                while (cause.InnerException is { } inner)
                {
                    cause = inner;
                }

                _root.GetService<IDiagnosticSink>().Publish(new DiagnosticEvent(
                    DiagnosticCode.UiStartupFailed,
                    DateTimeOffset.UtcNow,
                    ScanId: null,
                    CorrelationId: null,
                    new DiagnosticFields
                    {
                        Stage = "ui.startup",
                        ReasonCode = GetStartupFailureReason(ex),
                        Module = "SecurityReview.Desktop",
                        Method = "App.OnStartup",
                        AppVersion = typeof(App).Assembly.GetName().Version?.ToString(3),
                        ErrorCode = cause.HResult,
                    }));
                return Task.CompletedTask;
            });
        boundary.Install(this);

        try
        {
            // Open the main shell with its composed view model.
            var mainWindow = new MainWindow(_root.MainWindowViewModel, _root);
            MainWindow = mainWindow;
            mainWindow.Show();
            _ = InitializeRuntimeAsync(_root);
        }
        catch (Exception ex)
        {
            boundary.ReportStartupFailure(ex);
            MessageBox.Show(
                UiExceptionBoundary.StartupFailureMessage,
                "安全审查工具 - 启动失败",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    private static string GetStartupFailureReason(Exception exception) =>
        exception is XamlParseException ? "xaml_parse" : "unexpected_exception";

    private static async Task InitializeRuntimeAsync(CompositionRoot root)
    {
        try
        {
            await root.InitializeRuntimeAsync();
        }
        catch (Exception ex)
        {
            root.Health.MarkBlocked("runtime_initialization_failed");
            root.ErrorSink.Report(
                "runtime_initialization_failed",
                $"运行环境初始化失败：{AsyncRelayCommand.SanitizeMessage(ex)}");
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose(disposing: true);
        base.OnExit(e);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            _root?.Dispose();
            _root = null;
        }
        _disposed = true;
    }
}
