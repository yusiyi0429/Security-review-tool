using System.Windows;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop.Views;

/// <summary>
/// Modal update dialog. Shows the update state machine (status text +
/// progress), the 检查/下载并安装/取消/打开发布页 commands, and the
/// 启动时自动检查 opt-in bound to the settings store.
/// </summary>
public partial class UpdateWindow : Window
{
    private readonly UpdateViewModel _viewModel;
    private bool _hasInitialized;

    public UpdateWindow(UpdateViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        DataContext = viewModel;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;
        if (_hasInitialized)
            return;

        _hasInitialized = true;
        await _viewModel.InitializeAsync();
    }
}
