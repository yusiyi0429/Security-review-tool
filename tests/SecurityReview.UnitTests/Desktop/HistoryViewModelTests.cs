using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Desktop;

public sealed class HistoryViewModelTests
{
    [Fact]
    public async Task View_scan_command_requests_read_only_replay_for_row()
    {
        var errorSink = new TestErrorSink();
        var viewModel = new HistoryViewModel(
            () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(),
            errorSink);
        var scan = new ScanHistoryItem(
            new ScanId(Guid.NewGuid()),
            ScanStatus.Completed,
            DateTimeOffset.UtcNow.AddMinutes(-10),
            DateTimeOffset.UtcNow,
            "rulepack",
            "client",
            "pipeline",
            2,
            4,
            0);
        ScanId? requestedScanId = null;
        viewModel.ScanViewRequested += (scanId, _) =>
        {
            requestedScanId = scanId;
            return Task.CompletedTask;
        };

        Assert.True(viewModel.ViewScanCommand.CanExecute(scan));
        var command = Assert.IsType<AsyncRelayCommand>(
            viewModel.ViewScanCommand);
        await command.ExecuteAsync(scan);

        Assert.Equal(scan, viewModel.SelectedScan);
        Assert.Equal(scan.ScanId, requestedScanId);
        Assert.Empty(errorSink.Errors);
    }

    [Fact]
    public async Task View_scan_command_reports_when_shell_is_not_connected()
    {
        var errorSink = new TestErrorSink();
        var viewModel = new HistoryViewModel(
            () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(),
            () => throw new InvalidOperationException(),
            errorSink);
        var scan = new ScanHistoryItem(
            new ScanId(Guid.NewGuid()),
            ScanStatus.Completed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            "rulepack",
            "client",
            "pipeline",
            0,
            0,
            0);

        var command = Assert.IsType<AsyncRelayCommand>(
            viewModel.ViewScanCommand);
        await command.ExecuteAsync(scan);

        Assert.Contains(
            errorSink.Errors,
            error => error.Code == "history_view_unavailable");
    }

    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();

        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }
}
