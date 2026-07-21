using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop.Views;

/// <summary>
/// Code-behind for ScanResultsView. Handles mouse events for group
/// expansion and occurrence detail loading.
/// </summary>
public partial class ScanResultsView : UserControl
{
    public ScanResultsView()
    {
        InitializeComponent();
    }

    private void GroupItem_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not ScanResultsViewModel vm)
            return;

        if (sender is not FrameworkElement element || element.DataContext is null)
            return;

        // The actual command dispatch is handled by the view model's
        // ExpandGroupCommand. We trigger it here via the command parameter.
        if (vm.ExpandGroupCommand.CanExecute(element.DataContext))
        {
            vm.ExpandGroupCommand.Execute(element.DataContext);
        }
    }

    private void OccurrenceItem_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not ScanResultsViewModel vm)
            return;

        if (sender is not FrameworkElement element || element.DataContext is null)
            return;

        if (vm.SelectOccurrenceCommand.CanExecute(element.DataContext))
        {
            vm.SelectOccurrenceCommand.Execute(element.DataContext);
        }
    }
}
