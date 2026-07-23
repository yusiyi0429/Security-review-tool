using System.Windows;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop;

/// <summary>
/// Main application shell. Navigation sidebar, content area, and
/// status bar. No complete values are displayed in the window title
/// or status bar — only sanitized, redacted information.
/// </summary>
public partial class MainWindow : Window
{
    private const double PreferredWidth = 1280;
    private const double PreferredHeight = 760;
    private const double PreferredMinimumWidth = 960;
    private const double PreferredMinimumHeight = 600;

    private readonly MainWindowViewModel _viewModel;
    private readonly CompositionRoot _root;

    public MainWindow(MainWindowViewModel viewModel, CompositionRoot root)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(root);
        _viewModel = viewModel;
        _root = root;

        DataContext = _viewModel;
        InitializeComponent();
        FitInitialBoundsToWorkArea();

        // Subscribe to navigation changes and sync the content view
        _viewModel.NavigationService.Navigated += OnNavigated;
        _root.ErrorSink.ErrorReported += OnErrorReported;

        // Set initial view (新建扫描)
        OnNavigated(NavigationEntry.新建扫描);
    }

    private void OnNavigated(NavigationEntry entry)
    {
        object? view = entry switch
        {
            NavigationEntry.新建扫描 => _root.GetNewScanViewModel(),
            NavigationEntry.任务历史 => _root.GetHistoryViewModel(),
            NavigationEntry.规则管理 => _root.GetRuleManagementViewModel(),
            NavigationEntry.LLM设置 => _root.GetLlmSettingsViewModel(),
            NavigationEntry.诊断与帮助 => _root.GetCoverageViewModel(),
            _ => null
        };

        if (view is NewScanViewModel newScan)
        {
            newScan.ScanLaunchRequested += OnScanLaunchRequestedAsync;
        }

        _viewModel.CurrentView = view;
    }

    private async Task OnScanLaunchRequestedAsync(
        ScanLaunchRequest request,
        CancellationToken cancellationToken)
    {
        IScanOrchestrator orchestrator;
        try
        {
            orchestrator = _root.GetService<IScanOrchestrator>();
        }
        catch (InvalidOperationException)
        {
            _root.ErrorSink.Report(
                "scan_execution_unavailable",
                "扫描执行服务未成功初始化，请检查沙箱和规则包状态后重启应用。");
            return;
        }

        ScanProgressViewModel progressViewModel =
            _root.GetScanProgressViewModel(request.ScanId);
        _viewModel.CurrentView = progressViewModel;

        await foreach (ScanProgress progress in orchestrator.RunAsync(
            request.ScanId,
            request.Snapshot,
            cancellationToken))
        {
            progressViewModel.ApplyProgress(progress);
        }
    }

    private void OnErrorReported(UiErrorEntry entry)
    {
        if (Dispatcher.CheckAccess())
        {
            _viewModel.ShowError(entry.Message);
            return;
        }

        _ = Dispatcher.BeginInvoke(
            () => _viewModel.ShowError(entry.Message));
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.NavigationService.Navigated -= OnNavigated;
        _root.ErrorSink.ErrorReported -= OnErrorReported;
        base.OnClosed(e);
    }

    /// <summary>The view model instance backing this window.</summary>
    public MainWindowViewModel ViewModel => _viewModel;

    private void FitInitialBoundsToWorkArea()
    {
        Rect workArea = SystemParameters.WorkArea;
        if (workArea.IsEmpty || workArea.Width <= 0 || workArea.Height <= 0)
            return;

        // WPF dimensions are device-independent pixels, as is WorkArea. Clamp
        // before the first Show() so the native title bar and its window
        // controls remain reachable on 1366x768 screens and at high DPI.
        MinWidth = Math.Min(PreferredMinimumWidth, workArea.Width);
        MinHeight = Math.Min(PreferredMinimumHeight, workArea.Height);
        Width = Math.Min(PreferredWidth, workArea.Width);
        Height = Math.Min(PreferredHeight, workArea.Height);
        Left = workArea.Left + ((workArea.Width - Width) / 2);
        Top = workArea.Top + ((workArea.Height - Height) / 2);
    }
}
