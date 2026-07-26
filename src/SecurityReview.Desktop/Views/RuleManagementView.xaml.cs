using System.Windows;
using System.Windows.Controls;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop.Views;

/// <summary>
/// Code-behind for RuleManagementView.
/// </summary>
public partial class RuleManagementView : UserControl
{
    public RuleManagementView()
    {
        InitializeComponent();
    }

    private async void UserControl_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is RuleManagementViewModel viewModel)
            await viewModel.RefreshAsync();
    }
}
