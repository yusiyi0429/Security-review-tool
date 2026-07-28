using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for <see cref="MainWindowViewModel"/>: the status-bar update
/// badge (hidden by default, shown by <c>ShowUpdateAvailable</c>) and the
/// 检查更新 command that opens the update dialog through the injected seam.
/// </summary>
public sealed class MainWindowViewModelTests
{
    [Fact]
    public void update_badge_is_hidden_by_default()
    {
        var viewModel = CreateViewModel();

        Assert.False(viewModel.HasUpdateAvailable);
        Assert.Null(viewModel.UpdateBadgeText);
    }

    [Fact]
    public void show_update_available_sets_badge_text_and_raises_property_changed()
    {
        var viewModel = CreateViewModel();
        var changed = new List<string?>();
        viewModel.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        viewModel.ShowUpdateAvailable("1.2.3");

        Assert.True(viewModel.HasUpdateAvailable);
        Assert.Equal("有新版本 v1.2.3", viewModel.UpdateBadgeText);
        Assert.Contains(nameof(MainWindowViewModel.UpdateBadgeText), changed);
        Assert.Contains(nameof(MainWindowViewModel.HasUpdateAvailable), changed);
    }

    [Fact]
    public void show_update_available_rejects_blank_version()
    {
        var viewModel = CreateViewModel();

        Assert.Throws<ArgumentException>(() => viewModel.ShowUpdateAvailable(" "));
        Assert.False(viewModel.HasUpdateAvailable);
    }

    [Fact]
    public async Task check_updates_command_opens_update_window()
    {
        var openCount = 0;
        var viewModel = CreateViewModel(openUpdateWindow: () => openCount++);

        Assert.True(viewModel.CheckUpdatesCommand.CanExecute(null));
        await ((AsyncRelayCommand)viewModel.CheckUpdatesCommand).ExecuteAsync(null);

        Assert.Equal(1, openCount);
    }

    [Fact]
    public async Task check_updates_command_without_opener_is_a_no_op()
    {
        var sink = new RecordingErrorSink();
        var viewModel = CreateViewModel(sink: sink);

        await ((AsyncRelayCommand)viewModel.CheckUpdatesCommand).ExecuteAsync(null);

        Assert.Empty(sink.Errors);
    }

    private static MainWindowViewModel CreateViewModel(
        RecordingErrorSink? sink = null,
        Action? openUpdateWindow = null) =>
        new(
            new NavigationService(),
            new StartupHealthService(),
            sink ?? new RecordingErrorSink(),
            openUpdateWindow);

    private sealed class RecordingErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();

        public void Report(string code, string message) => Errors.Add((code, message));
    }
}
