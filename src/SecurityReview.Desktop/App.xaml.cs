using System.Windows;
using SecurityReview.Desktop.Services;

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

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Build the composition root with production paths.
        _root = new CompositionRoot(CompositionRoot.Args.ForProduction());

        // Install the global UI exception boundary.
        var boundary = new UiExceptionBoundary(
            _root.ErrorSink,
            async ex =>
            {
                // Emit redacted diagnostic to the configured sink.
                // In production, this would persist to the diagnostics store.
                await Task.CompletedTask;
            });
        boundary.Install(this);

        // Open the main shell with its composed view model.
        var mainWindow = new MainWindow(_root.MainWindowViewModel);
        mainWindow.Show();
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
