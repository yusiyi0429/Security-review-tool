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

    public MainWindow(MainWindowViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        _viewModel = viewModel;

        DataContext = _viewModel;
        InitializeComponent();
    }

    /// <summary>The view model instance backing this window.</summary>
    public MainWindowViewModel ViewModel => _viewModel;
}
