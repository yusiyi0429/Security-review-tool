using System.Windows;
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

        // Subscribe to navigation changes and sync the content view
        _viewModel.NavigationService.Navigated += OnNavigated;

        // Set initial view (新建扫描)
        OnNavigated(NavigationEntry.新建扫描);
    }

    private void OnNavigated(NavigationEntry entry)
    {
        _viewModel.CurrentView = entry switch
        {
            NavigationEntry.新建扫描 => _root.GetNewScanViewModel(),
            NavigationEntry.任务历史 => _root.GetHistoryViewModel(),
            NavigationEntry.规则管理 => _root.GetRuleManagementViewModel(),
            NavigationEntry.LLM设置 => _root.GetLlmSettingsViewModel(),
            NavigationEntry.诊断与帮助 => _root.GetCoverageViewModel(),
            _ => null
        };
    }

    /// <summary>The view model instance backing this window.</summary>
    public MainWindowViewModel ViewModel => _viewModel;
}
