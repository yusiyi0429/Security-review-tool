namespace SecurityReview.Desktop.Services;

/// <summary>
/// Navigation entries for the main shell navigation bar.
/// </summary>
public enum NavigationEntry
{
    新建扫描,
    任务历史,
    规则管理,
    LLM设置,
    诊断与帮助,
}

/// <summary>
/// Simple navigation service for the main window shell.
/// Tracks the current navigation entry and exposes events for view switching.
/// No DI/MVVM package — manual composition.
/// </summary>
public sealed class NavigationService
{
    private NavigationEntry _current;

    /// <summary>Fires when the current entry changes.</summary>
    public event Action<NavigationEntry>? Navigated;

    /// <summary>The currently selected navigation entry.</summary>
    public NavigationEntry CurrentEntry
    {
        get => _current;
        set
        {
            if (_current == value) return;
            _current = value;
            Navigated?.Invoke(_current);
        }
    }

    /// <summary>Navigates to the specified entry.</summary>
    public void NavigateTo(NavigationEntry entry)
    {
        CurrentEntry = entry;
    }
}
