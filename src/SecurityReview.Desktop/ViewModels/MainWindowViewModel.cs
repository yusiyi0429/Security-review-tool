using System.ComponentModel;
using System.Windows.Input;
using SecurityReview.Desktop.Services;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the main application shell.
/// Exposes navigation commands, status bar information, and
/// the startup health state.
/// </summary>
public sealed class MainWindowViewModel : ObservableObject
{
    private readonly NavigationService _navigation;
    private readonly StartupHealthService _health;
    private readonly IUiErrorSink _errorSink;
    private readonly Action? _openUpdateWindow;

    private string _rulePackageVersion = "";
    private string _sandboxHealth = "检查中…";
    private string _llmState = "未配置";
    private string _appVersion = "";
    private string? _updateBadgeText;
    private bool _nonLatestRuleWarning;
    private bool _scanEnabled;
    private object? _currentView;
    private string _errorMessage = "";
    private bool _hasError;

    public MainWindowViewModel(
        NavigationService navigation,
        StartupHealthService health,
        IUiErrorSink errorSink,
        Action? openUpdateWindow = null)
    {
        _navigation = navigation ?? throw new ArgumentNullException(nameof(navigation));
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _openUpdateWindow = openUpdateWindow;

        NavigateCommand = new AsyncRelayCommand(
            param => NavigateToAsync((NavigationEntry)param!),
            errorSink);
        DismissErrorCommand = new AsyncRelayCommand(
            _ => DismissErrorAsync(),
            errorSink);
        CheckUpdatesCommand = new AsyncRelayCommand(
            _ => OpenUpdateWindow(),
            errorSink);

        _health.PropertyChanged += OnHealthChanged;
        SyncHealthState();
    }

    // ------------------------------------------------------------------ Navigation commands

    public ICommand NavigateCommand { get; }
    public ICommand DismissErrorCommand { get; }

    /// <summary>检查更新 — opens the modal update dialog.</summary>
    public ICommand CheckUpdatesCommand { get; }

    /// <summary>The navigation service instance for the shell.</summary>
    public NavigationService NavigationService => _navigation;

    /// <summary>The currently selected navigation entry.</summary>
    public NavigationEntry CurrentEntry
    {
        get => _navigation.CurrentEntry;
        set => _navigation.CurrentEntry = value;
    }

    /// <summary>The view model for the currently active content view.</summary>
    public object? CurrentView
    {
        get => _currentView;
        set => SetProperty(ref _currentView, value);
    }

    private Task NavigateToAsync(NavigationEntry entry)
    {
        _navigation.NavigateTo(entry);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ Status bar properties

    /// <summary>Active rule package version string.</summary>
    public string RulePackageVersion
    {
        get => _rulePackageVersion;
        set => SetProperty(ref _rulePackageVersion, value);
    }

    /// <summary>Sandbox health display string.</summary>
    public string SandboxHealth
    {
        get => _sandboxHealth;
        set => SetProperty(ref _sandboxHealth, value);
    }

    /// <summary>LLM connection state display string.</summary>
    public string LlmState
    {
        get => _llmState;
        set => SetProperty(ref _llmState, value);
    }

    /// <summary>Application version string.</summary>
    public string AppVersion
    {
        get => _appVersion;
        set => SetProperty(ref _appVersion, value);
    }

    /// <summary>
    /// Status-bar badge text shown when a newer stable release exists
    /// (e.g. 有新版本 v1.2.3); <c>null</c> when no update is known.
    /// </summary>
    public string? UpdateBadgeText
    {
        get => _updateBadgeText;
        private set
        {
            if (SetProperty(ref _updateBadgeText, value))
                OnPropertyChanged(nameof(HasUpdateAvailable));
        }
    }

    /// <summary>Whether the update-available badge is visible.</summary>
    public bool HasUpdateAvailable => !string.IsNullOrEmpty(UpdateBadgeText);

    /// <summary>
    /// Shows the status-bar update badge for the supplied latest version
    /// (<c>major.minor.patch</c> display form). Called by the composition
    /// root after a background startup check; it only sets the badge and
    /// never triggers a download.
    /// </summary>
    public void ShowUpdateAvailable(string latestVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(latestVersion);
        UpdateBadgeText = $"有新版本 v{latestVersion}";
    }

    private Task OpenUpdateWindow()
    {
        _openUpdateWindow?.Invoke();
        return Task.CompletedTask;
    }

    /// <summary>True when a newer rule package is available.</summary>
    public bool NonLatestRuleWarning
    {
        get => _nonLatestRuleWarning;
        set => SetProperty(ref _nonLatestRuleWarning, value);
    }

    /// <summary>Whether the Start Scan button should be enabled.</summary>
    public bool ScanEnabled
    {
        get => _scanEnabled;
        set => SetProperty(ref _scanEnabled, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        private set => SetProperty(ref _errorMessage, value);
    }

    public bool HasError
    {
        get => _hasError;
        private set => SetProperty(ref _hasError, value);
    }

    public void ShowError(string message)
    {
        ErrorMessage = message;
        HasError = !string.IsNullOrWhiteSpace(message);
    }

    private Task DismissErrorAsync()
    {
        HasError = false;
        ErrorMessage = "";
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ Health sync

    private void OnHealthChanged(object? sender, PropertyChangedEventArgs e)
    {
        SyncHealthState();
    }

    private void SyncHealthState()
    {
        ScanEnabled = _health.CanStartScan;

        SandboxHealth = _health.State switch
        {
            StartupHealthState.Checking => "检查中…",
            StartupHealthState.Ready => "正常",
            StartupHealthState.Blocked => $"已阻止 ({_health.BlockedCode})",
            _ => "未知",
        };
    }
}
