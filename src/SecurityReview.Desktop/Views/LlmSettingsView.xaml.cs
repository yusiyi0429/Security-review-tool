using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop.Views;

/// <summary>
/// Code-behind for LlmSettingsView.
/// </summary>
public partial class LlmSettingsView : UserControl
{
    private LlmSettingsViewModel? _viewModel;
    private bool _isSynchronizingPassword;
    private bool _hasLoadedConfiguration;

    public LlmSettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;
        if (_hasLoadedConfiguration || _viewModel is null)
            return;

        _hasLoadedConfiguration = true;
        await _viewModel.LoadConfigAsync();
    }

    private void OnDataContextChanged(
        object sender, DependencyPropertyChangedEventArgs e)
    {
        _ = sender;
        if (_viewModel is not null)
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;

        _hasLoadedConfiguration = false;
        _viewModel = e.NewValue as LlmSettingsViewModel;
        if (_viewModel is not null)
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;

        ClearPasswordBox();
    }

    private void OnApiKeyPasswordChanged(object sender, RoutedEventArgs e)
    {
        _ = e;
        if (_isSynchronizingPassword || _viewModel is null)
            return;

        _viewModel.CredentialInput = ((PasswordBox)sender).Password;
    }

    private void OnViewModelPropertyChanged(
        object? sender, PropertyChangedEventArgs e)
    {
        _ = sender;
        if (e.PropertyName == nameof(LlmSettingsViewModel.CredentialInput)
            && string.IsNullOrEmpty(_viewModel?.CredentialInput))
        {
            if (Dispatcher.CheckAccess())
                ClearPasswordBox();
            else
                _ = Dispatcher.BeginInvoke((Action)ClearPasswordBox);
        }
    }

    private void ClearPasswordBox()
    {
        if (string.IsNullOrEmpty(ApiKeyBox.Password))
            return;

        _isSynchronizingPassword = true;
        try
        {
            ApiKeyBox.Clear();
        }
        finally
        {
            _isSynchronizingPassword = false;
        }
    }
}
