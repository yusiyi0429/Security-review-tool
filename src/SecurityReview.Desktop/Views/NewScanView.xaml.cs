using System.Windows;
using System.Windows.Controls;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.Desktop.Views;

/// <summary>
/// Code-behind for NewScanView. Handles drag-drop and connects the view
/// to its view model.
/// </summary>
public partial class NewScanView : UserControl
{
    public NewScanView()
    {
        InitializeComponent();
    }

    private async void UserControl_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is NewScanViewModel vm)
        {
            await vm.InitializeAsync();
        }
    }

    private void UserControl_Drop(object sender, DragEventArgs e)
    {
        if (DataContext is not NewScanViewModel vm)
            return;

        if (!FileDropService.CanAcceptDrop(e.Data))
            return;

        IReadOnlyList<string> paths = FileDropService.ExtractPaths(e.Data);
        foreach (string path in paths)
        {
            vm.AddTargetFromDrop(path);
        }
    }

    private void UserControl_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = FileDropService.CanAcceptDrop(e.Data)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }
}
