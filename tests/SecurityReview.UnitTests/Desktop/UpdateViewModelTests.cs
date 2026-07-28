using SecurityReview.Application.Updates;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Infrastructure.Updates;

namespace SecurityReview.UnitTests.Desktop;

public sealed class UpdateViewModelTests
{
    private static readonly Uri ReleasePage = new("https://updates.example.com/releases/v1.1.0");

    [Fact]
    public void initial_state_is_idle()
    {
        var viewModel = CreateViewModel(new FakeAppUpdateService());

        Assert.Equal(UpdateViewModelState.Idle, viewModel.State);
        Assert.False(viewModel.IsBusy);
        Assert.False(viewModel.UpdateAvailable);
        Assert.False(viewModel.InstallCommand.CanExecute(null));
        Assert.False(viewModel.CancelCommand.CanExecute(null));
    }

    [Fact]
    public async Task initialize_loads_settings_without_saving()
    {
        var store = new FakeAppSettingsStore
        {
            StoredSettings = new AppSettings(AutoCheckUpdatesOnStartup: true),
        };
        var viewModel = CreateViewModel(new FakeAppUpdateService(), store: store);

        await viewModel.InitializeAsync();

        Assert.True(viewModel.AutoCheckUpdatesOnStartup);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task auto_check_toggle_persists_settings_immediately()
    {
        var store = new FakeAppSettingsStore();
        var viewModel = CreateViewModel(new FakeAppUpdateService(), store: store);

        viewModel.AutoCheckUpdatesOnStartup = true;
        for (int i = 0; i < 100 && store.SaveCount == 0; i++)
            await Task.Delay(10);

        Assert.Equal(1, store.SaveCount);
        Assert.NotNull(store.LastSaved);
        Assert.True(store.LastSaved!.AutoCheckUpdatesOnStartup);
    }

    [Fact]
    public async Task check_with_no_update_moves_to_no_update_state()
    {
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(updateAvailable: false),
        };
        var viewModel = CreateViewModel(service);

        await viewModel.CheckForUpdateAsync();

        Assert.Equal(UpdateViewModelState.NoUpdate, viewModel.State);
        Assert.Contains("最新", viewModel.StatusText);
        Assert.False(viewModel.UpdateAvailable);
        Assert.False(viewModel.InstallCommand.CanExecute(null));
    }

    [Fact]
    public async Task check_with_update_moves_to_update_available_and_enables_install()
    {
        var service = new FakeAppUpdateService { CheckResult = CreateCheckResult() };
        var viewModel = CreateViewModel(service);

        await viewModel.CheckForUpdateAsync();

        Assert.Equal(UpdateViewModelState.UpdateAvailable, viewModel.State);
        Assert.True(viewModel.UpdateAvailable);
        Assert.Contains("1.1.0", viewModel.StatusText);
        Assert.Contains("1.0.0", viewModel.CurrentVersionDisplay);
        Assert.True(viewModel.InstallCommand.CanExecute(null));
        Assert.False(viewModel.ShowPortableHint);
    }

    [Fact]
    public async Task portable_install_disables_install_and_shows_manual_hint()
    {
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(isPortableInstall: true),
        };
        var viewModel = CreateViewModel(service);

        await viewModel.CheckForUpdateAsync();

        Assert.Equal(UpdateViewModelState.UpdateAvailable, viewModel.State);
        Assert.True(viewModel.IsPortableInstall);
        Assert.True(viewModel.ShowPortableHint);
        Assert.False(viewModel.InstallCommand.CanExecute(null));
    }

    [Fact]
    public async Task portable_install_offers_release_page_instead_of_download()
    {
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(isPortableInstall: true),
        };
        Uri? opened = null;
        var viewModel = CreateViewModel(
            service,
            openReleasePage: url => { opened = url; return true; });

        await viewModel.CheckForUpdateAsync();

        Assert.True(viewModel.OpenReleasePageCommand.CanExecute(null));
        await viewModel.OpenReleasePage();

        Assert.Equal(ReleasePage, opened);
        Assert.Equal(0, service.DownloadCallCount);
    }

    [Fact]
    public async Task release_page_declined_or_failed_reports_error()
    {
        var service = new FakeAppUpdateService { CheckResult = CreateCheckResult() };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink, openReleasePage: _ => false);

        await viewModel.CheckForUpdateAsync();
        await viewModel.OpenReleasePage();

        Assert.True(sink.ContainsCode("open_release_page_failed"));
    }

    [Fact]
    public async Task cancel_command_raises_can_execute_changed_when_busy_state_changes()
    {
        var viewModel = CreateViewModel(new FakeAppUpdateService());
        int raised = 0;
        viewModel.CancelCommand.CanExecuteChanged += (_, _) => raised++;

        await viewModel.CheckForUpdateAsync();

        // Idle→Checking and Checking→NoUpdate each raise the event.
        Assert.True(raised >= 2);
        Assert.False(viewModel.CancelCommand.CanExecute(null));
    }

    [Fact]
    public async Task open_release_page_command_raises_can_execute_changed_when_result_arrives()
    {
        var service = new FakeAppUpdateService { CheckResult = CreateCheckResult() };
        var viewModel = CreateViewModel(service, openReleasePage: _ => true);
        int raised = 0;
        viewModel.OpenReleasePageCommand.CanExecuteChanged += (_, _) => raised++;
        Assert.False(viewModel.OpenReleasePageCommand.CanExecute(null));

        await viewModel.CheckForUpdateAsync();

        Assert.True(raised >= 1);
        Assert.True(viewModel.OpenReleasePageCommand.CanExecute(null));
    }

    [Fact]
    public async Task network_failure_during_check_reports_stable_message()
    {
        var service = new FakeAppUpdateService
        {
            CheckException = new HttpRequestException("connection to secret-host refused"),
        };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink);

        await viewModel.CheckForUpdateAsync();

        Assert.Equal(UpdateViewModelState.Failed, viewModel.State);
        Assert.True(sink.ContainsCode("update_network_failed"));
        Assert.DoesNotContain("secret-host", sink.Errors[0].Message);
    }

    [Fact]
    public async Task allowlist_violation_during_download_reports_stable_message()
    {
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(),
            DownloadException = new InvalidOperationException("host is not allowlisted"),
        };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink);

        await viewModel.CheckForUpdateAsync();
        await viewModel.DownloadAndInstallAsync();

        Assert.Equal(UpdateViewModelState.Failed, viewModel.State);
        Assert.True(sink.ContainsCode("update_source_not_allowed"));
    }

    [Fact]
    public async Task verification_failure_reports_and_moves_to_failed()
    {
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(),
            DownloadException = new UpdateVerificationException(
                "sha256 mismatch: expected deadbeef from https://files.example.com/x"),
        };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink);

        await viewModel.CheckForUpdateAsync();
        await viewModel.DownloadAndInstallAsync();

        Assert.Equal(UpdateViewModelState.Failed, viewModel.State);
        Assert.True(sink.ContainsCode("update_verification_failed"));
        Assert.Contains("校验失败", viewModel.StatusText);
        Assert.DoesNotContain("deadbeef", sink.Errors[0].Message);
        Assert.DoesNotContain("files.example.com", sink.Errors[0].Message);
    }

    [Fact]
    public async Task install_invokes_apply_callback_with_download_result()
    {
        var download = new AppDownloadResult("C:\\temp\\setup.exe", "abc123");
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(),
            DownloadResult = download,
        };
        AppDownloadResult? applied = null;
        var viewModel = CreateViewModel(
            service,
            applyUpdate: result => { applied = result; return Task.FromResult(true); });

        await viewModel.CheckForUpdateAsync();
        await viewModel.DownloadAndInstallAsync();

        Assert.Equal(UpdateViewModelState.ReadyToInstall, viewModel.State);
        Assert.Equal(100, viewModel.DownloadPercent);
        Assert.Same(download, applied);
        Assert.Contains("安装程序已启动", viewModel.StatusText);
    }

    [Fact]
    public async Task apply_failure_does_not_show_success_status()
    {
        var service = new FakeAppUpdateService { CheckResult = CreateCheckResult() };
        var viewModel = CreateViewModel(
            service,
            applyUpdate: _ => Task.FromResult(false));

        await viewModel.CheckForUpdateAsync();
        await viewModel.DownloadAndInstallAsync();

        Assert.Equal(UpdateViewModelState.ReadyToInstall, viewModel.State);
        Assert.Contains("未能启动", viewModel.StatusText);
        Assert.DoesNotContain("安装程序已启动", viewModel.StatusText);
    }

    [Fact]
    public async Task cancel_during_download_returns_to_update_available()
    {
        var downloadStarted = new TaskCompletionSource();
        var service = new FakeAppUpdateService
        {
            CheckResult = CreateCheckResult(),
            DownloadHandler = async cancellationToken =>
            {
                downloadStarted.SetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return new AppDownloadResult("unused", "unused");
            },
        };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink);

        await viewModel.CheckForUpdateAsync();
        Task installTask = ((AsyncRelayCommand)viewModel.InstallCommand).ExecuteAsync(null);
        await downloadStarted.Task;
        Assert.Equal(UpdateViewModelState.Downloading, viewModel.State);

        await viewModel.CancelPending();
        await installTask;

        Assert.Equal(UpdateViewModelState.UpdateAvailable, viewModel.State);
        Assert.Equal("已取消下载。", viewModel.StatusText);
        Assert.Empty(sink.Errors);
    }

    [Fact]
    public async Task cancel_during_check_returns_to_idle()
    {
        var checkStarted = new TaskCompletionSource();
        var service = new FakeAppUpdateService
        {
            CheckHandler = async cancellationToken =>
            {
                checkStarted.SetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return CreateCheckResult(updateAvailable: false);
            },
        };
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(service, sink: sink);

        Task checkTask = ((AsyncRelayCommand)viewModel.CheckCommand).ExecuteAsync(null);
        await checkStarted.Task;
        Assert.Equal(UpdateViewModelState.Checking, viewModel.State);
        Assert.True(viewModel.CancelCommand.CanExecute(null));

        await viewModel.CancelPending();
        await checkTask;

        Assert.Equal(UpdateViewModelState.Idle, viewModel.State);
        Assert.Empty(sink.Errors);
    }

    // ------------------------------------------------------------------ Helpers

    private static UpdateViewModel CreateViewModel(
        FakeAppUpdateService service,
        RecordingErrorSink? sink = null,
        FakeAppSettingsStore? store = null,
        Func<AppDownloadResult, Task<bool>>? applyUpdate = null,
        Func<Uri, bool>? openReleasePage = null) =>
        new(
            service,
            store ?? new FakeAppSettingsStore(),
            sink ?? new RecordingErrorSink(),
            applyUpdate,
            openReleasePage);

    private static AppUpdateCheckResult CreateCheckResult(
        bool updateAvailable = true,
        bool isPortableInstall = false) =>
        new(
            CurrentVersion: "1.0.0",
            LatestVersion: updateAvailable ? "1.1.0" : "1.0.0",
            UpdateAvailable: updateAvailable,
            InstallerUrl: updateAvailable ? new Uri("https://updates.example.com/setup.exe") : null,
            Sha256Url: updateAvailable ? new Uri("https://updates.example.com/setup.exe.sha256") : null,
            ReleasePageUrl: ReleasePage,
            IsPortableInstall: isPortableInstall);

    private sealed class FakeAppUpdateService : IAppUpdateService
    {
        public AppUpdateCheckResult CheckResult { get; set; } = CreateCheckResult(updateAvailable: false);
        public Exception? CheckException { get; set; }
        public Exception? DownloadException { get; set; }
        public AppDownloadResult DownloadResult { get; set; } = new("C:\\temp\\setup.exe", "abc123");
        public Func<CancellationToken, Task<AppUpdateCheckResult>>? CheckHandler { get; set; }
        public Func<CancellationToken, Task<AppDownloadResult>>? DownloadHandler { get; set; }
        public int DownloadCallCount { get; private set; }

        public Task<AppUpdateCheckResult> CheckForUpdateAsync(CancellationToken cancellationToken)
        {
            if (CheckHandler is not null)
                return CheckHandler(cancellationToken);
            if (CheckException is not null)
                return Task.FromException<AppUpdateCheckResult>(CheckException);
            return Task.FromResult(CheckResult);
        }

        public Task<AppDownloadResult> DownloadInstallerAsync(
            AppUpdateCheckResult check,
            IProgress<int>? progress,
            CancellationToken cancellationToken)
        {
            DownloadCallCount++;
            if (DownloadHandler is not null)
                return DownloadHandler(cancellationToken);
            if (DownloadException is not null)
                return Task.FromException<AppDownloadResult>(DownloadException);
            progress?.Report(50);
            progress?.Report(100);
            return Task.FromResult(DownloadResult);
        }
    }

    private sealed class FakeAppSettingsStore : IAppSettingsStore
    {
        public AppSettings StoredSettings { get; set; } = AppSettings.Default;
        public int SaveCount { get; private set; }
        public AppSettings? LastSaved { get; private set; }

        public Task<AppSettings> LoadAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(StoredSettings);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            SaveCount++;
            LastSaved = settings;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();

        public void Report(string code, string message) => Errors.Add((code, message));

        public bool ContainsCode(string code) => Errors.Exists(error => error.Code == code);
    }
}
