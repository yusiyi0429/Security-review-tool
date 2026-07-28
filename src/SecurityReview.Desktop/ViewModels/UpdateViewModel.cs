using System.Net.Http;
using System.Windows.Input;
using SecurityReview.Application.Updates;
using SecurityReview.Desktop.Services;
using SecurityReview.Infrastructure.Updates;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the in-app update dialog. Drives the state machine
/// 空闲/检查中/无更新/有更新/下载中(百分比)/待安装/失败 around
/// <see cref="IAppUpdateService"/>. Portable installs never auto-install:
/// the only offered action is opening the release page (via an injected
/// opener that must re-confirm before any external open, following the
/// ExplorerService pattern). The actual install-and-restart lives outside
/// this view model: <see cref="InstallCommand"/> downloads and verifies the
/// installer, then hands the result to the injected apply callback
/// (constructor seam, wired by the composition root). The callback never
/// throws and returns whether the installer actually started, so the
/// success text is only shown on a real start. All failures are
/// reported through <see cref="IUiErrorSink"/> with stable codes and
/// sanitized Chinese messages — never raw exception text, URLs, or paths.
/// </summary>
public sealed class UpdateViewModel : ObservableObject
{
    private readonly IAppUpdateService _updateService;
    private readonly IAppSettingsStore _settingsStore;
    private readonly IUiErrorSink _errorSink;
    private readonly Func<AppDownloadResult, Task<bool>>? _applyUpdate;
    private readonly Func<Uri, bool>? _openReleasePage;

    private AppUpdateCheckResult? _lastCheck;
    private UpdateViewModelState _state = UpdateViewModelState.Idle;
    private string _statusText = "尚未检查更新。";
    private int _downloadPercent;
    private bool _autoCheckUpdatesOnStartup;
    private bool _isLoadingSettings;

    public UpdateViewModel(
        IAppUpdateService updateService,
        IAppSettingsStore settingsStore,
        IUiErrorSink errorSink,
        Func<AppDownloadResult, Task<bool>>? applyUpdate = null,
        Func<Uri, bool>? openReleasePage = null)
    {
        _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _applyUpdate = applyUpdate;
        _openReleasePage = openReleasePage;

        CheckCommand = new AsyncRelayCommand(
            (_, ct) => CheckForUpdateAsync(ct), errorSink,
            _ => State != UpdateViewModelState.Downloading);
        InstallCommand = new AsyncRelayCommand(
            (_, ct) => DownloadAndInstallAsync(ct), errorSink,
            _ => State == UpdateViewModelState.UpdateAvailable && !IsPortableInstall);
        CancelCommand = new AsyncRelayCommand(
            _ => CancelPending(), errorSink,
            _ => IsBusy);
        OpenReleasePageCommand = new AsyncRelayCommand(
            _ => OpenReleasePage(), errorSink,
            _ => CanOpenReleasePage);

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(State) or nameof(IsPortableInstall))
                CommandManager.InvalidateRequerySuggested();
        };
    }

    // ------------------------------------------------------------------ Commands

    /// <summary>检查 — queries for a newer stable release.</summary>
    public ICommand CheckCommand { get; }

    /// <summary>下载并安装 — downloads, verifies, then invokes the apply seam.</summary>
    public ICommand InstallCommand { get; }

    /// <summary>取消 — cancels the in-flight check or download.</summary>
    public ICommand CancelCommand { get; }

    /// <summary>打开发布页 — opens the release page via the confirming opener.</summary>
    public ICommand OpenReleasePageCommand { get; }

    // ------------------------------------------------------------------ Properties

    public UpdateViewModelState State
    {
        get => _state;
        private set
        {
            if (SetProperty(ref _state, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                OnPropertyChanged(nameof(IsProgressVisible));
                OnPropertyChanged(nameof(IsProgressIndeterminate));
                ((AsyncRelayCommand)CheckCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)InstallCommand).RaiseCanExecuteChanged();
                ((AsyncRelayCommand)CancelCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        private set => SetProperty(ref _statusText, value);
    }

    public int DownloadPercent
    {
        get => _downloadPercent;
        private set => SetProperty(ref _downloadPercent, value);
    }

    /// <summary>Whether a check or download is in flight.</summary>
    public bool IsBusy => State is UpdateViewModelState.Checking or UpdateViewModelState.Downloading;

    public bool IsProgressVisible => IsBusy;

    public bool IsProgressIndeterminate => State == UpdateViewModelState.Checking;

    /// <summary>Version line for the dialog header.</summary>
    public string CurrentVersionDisplay => _lastCheck is null
        ? "当前版本: —"
        : $"当前版本: {_lastCheck.CurrentVersion}";

    /// <summary>Whether the last check found a newer stable release.</summary>
    public bool UpdateAvailable => _lastCheck?.UpdateAvailable == true;

    /// <summary>Whether this is a portable install (no automatic install).</summary>
    public bool IsPortableInstall => _lastCheck?.IsPortableInstall == true;

    /// <summary>Whether the portable-install manual-download hint is shown.</summary>
    public bool ShowPortableHint => UpdateAvailable && IsPortableInstall;

    /// <summary>Whether a release page can be opened (result + wired opener).</summary>
    public bool CanOpenReleasePage => _lastCheck is not null && _openReleasePage is not null;

    /// <summary>
    /// 启动时自动检查 opt-in. Toggling persists immediately through
    /// <see cref="IAppSettingsStore"/>; save failures are reported to the
    /// error sink and never throw out of the setter.
    /// </summary>
    public bool AutoCheckUpdatesOnStartup
    {
        get => _autoCheckUpdatesOnStartup;
        set
        {
            if (SetProperty(ref _autoCheckUpdatesOnStartup, value) && !_isLoadingSettings)
                _ = PersistAutoCheckAsync(value);
        }
    }

    // ------------------------------------------------------------------ Operations

    /// <summary>Loads persisted settings without re-saving them.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            AppSettings settings = await _settingsStore.LoadAsync(cancellationToken);
            _isLoadingSettings = true;
            try
            {
                AutoCheckUpdatesOnStartup = settings.AutoCheckUpdatesOnStartup;
            }
            finally
            {
                _isLoadingSettings = false;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Dialog closed while loading; nothing to report.
        }
        catch (Exception)
        {
            _errorSink.Report("update_settings_load_failed", "读取更新设置失败。");
        }
    }

    /// <summary>Runs the version check and moves the state machine.</summary>
    public async Task CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        State = UpdateViewModelState.Checking;
        StatusText = "正在检查更新…";
        DownloadPercent = 0;
        try
        {
            AppUpdateCheckResult result = await _updateService
                .CheckForUpdateAsync(cancellationToken);
            ApplyCheckResult(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            State = UpdateViewModelState.Idle;
            StatusText = "已取消检查。";
        }
        catch (Exception ex)
        {
            ReportFailure(ex, "检查更新失败，请稍后重试。");
        }
    }

    /// <summary>
    /// Downloads the verified installer, then invokes the injected apply
    /// callback. Portable installs and stale state are refused up front.
    /// </summary>
    public async Task DownloadAndInstallAsync(CancellationToken cancellationToken = default)
    {
        if (_lastCheck is not { UpdateAvailable: true } check || check.IsPortableInstall)
            return;

        State = UpdateViewModelState.Downloading;
        DownloadPercent = 0;
        StatusText = "正在下载更新… 0%";
        var progress = new Progress<int>(percent =>
        {
            DownloadPercent = percent;
            StatusText = $"正在下载更新… {percent}%";
        });
        try
        {
            AppDownloadResult download = await _updateService
                .DownloadInstallerAsync(check, progress, cancellationToken);

            DownloadPercent = 100;
            State = UpdateViewModelState.ReadyToInstall;
            if (_applyUpdate is not null)
            {
                StatusText = "下载完成，正在启动安装程序…";
                bool applied = await _applyUpdate(download);
                StatusText = applied
                    ? "安装程序已启动，应用将在安装完成后重新启动。"
                    : "安装程序未能启动。请前往发布页手动下载安装，或重新检查更新。";
            }
            else
            {
                StatusText = "下载完成，等待安装。";
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The update is still available; let the user retry.
            State = UpdateViewModelState.UpdateAvailable;
            StatusText = "已取消下载。";
        }
        catch (Exception ex)
        {
            string fallback = ex is UpdateVerificationException
                ? "下载文件的完整性校验失败，已删除下载内容。请重新检查更新，或前往发布页手动下载。"
                : "下载更新失败，请重新检查更新或稍后再试。";
            ReportFailure(ex, fallback);
        }
    }

    /// <summary>Cancels the in-flight check or download, if any.</summary>
    public Task CancelPending()
    {
        ((AsyncRelayCommand)CheckCommand).Cancel();
        ((AsyncRelayCommand)InstallCommand).Cancel();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Opens the release page through the injected opener. The opener must
    /// show the external-open confirmation itself and return false when the
    /// user declines or the open fails.
    /// </summary>
    public Task OpenReleasePage()
    {
        if (_lastCheck is null || _openReleasePage is null)
            return Task.CompletedTask;

        if (!_openReleasePage(_lastCheck.ReleasePageUrl))
            _errorSink.Report("open_release_page_failed", "无法打开发布页面。");

        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------ Helpers

    private void ApplyCheckResult(AppUpdateCheckResult result)
    {
        _lastCheck = result;
        OnPropertyChanged(nameof(CurrentVersionDisplay));
        OnPropertyChanged(nameof(UpdateAvailable));
        OnPropertyChanged(nameof(IsPortableInstall));
        OnPropertyChanged(nameof(ShowPortableHint));
        OnPropertyChanged(nameof(CanOpenReleasePage));
        ((AsyncRelayCommand)InstallCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)OpenReleasePageCommand).RaiseCanExecuteChanged();

        if (!result.UpdateAvailable)
        {
            State = UpdateViewModelState.NoUpdate;
            StatusText = $"当前已是最新版本（{result.CurrentVersion}）。";
        }
        else
        {
            State = UpdateViewModelState.UpdateAvailable;
            StatusText = result.IsPortableInstall
                ? $"发现新版本 {result.LatestVersion}（当前 {result.CurrentVersion}）。便携版请前往发布页手动下载更新。"
                : $"发现新版本 {result.LatestVersion}（当前 {result.CurrentVersion}）。";
        }
    }

    private async Task PersistAutoCheckAsync(bool enabled)
    {
        try
        {
            await _settingsStore.SaveAsync(new AppSettings(enabled));
        }
        catch (Exception)
        {
            _errorSink.Report("update_settings_save_failed", "保存更新设置失败。");
        }
    }

    private void ReportFailure(Exception exception, string fallbackStatus)
    {
        State = UpdateViewModelState.Failed;
        (string code, string message) = exception switch
        {
            UpdateVerificationException => (
                "update_verification_failed", "更新文件校验失败，已删除下载内容。"),
            InvalidOperationException => (
                "update_source_not_allowed", "更新来源未通过安全校验。"),
            HttpRequestException or TaskCanceledException or UriFormatException => (
                "update_network_failed", "无法连接更新服务器，请检查网络后重试。"),
            _ => ("update_failed", "更新操作失败。"),
        };
        StatusText = fallbackStatus;
        _errorSink.Report(code, message);
    }
}
