using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// Minimal INotifyPropertyChanged base for view models.
/// No DI/MVVM package dependency — manual composition only.
/// </summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Sets the backing field and raises PropertyChanged if the value changed.
    /// </summary>
    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        OnPropertyChanged(propertyName!);
        return true;
    }

    /// <summary>
    /// Raises the PropertyChanged event.
    /// </summary>
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName!));
    }
}
