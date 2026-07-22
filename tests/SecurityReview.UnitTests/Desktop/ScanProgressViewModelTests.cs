using System.ComponentModel;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for ScanProgressViewModel: stage binding, progress coalescing,
/// cancel idempotent behaviour, "正在停止新任务" display, terminal state
/// handling, and property change notifications.
/// </summary>
public sealed class ScanProgressViewModelTests
{
    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();
        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }

    private static ScanProgressViewModel CreateViewModel(
        TestErrorSink? sink = null,
        CancelScanHandler? cancelHandler = null)
    {
        sink ??= new TestErrorSink();
        return new ScanProgressViewModel(
            sink,
            () => cancelHandler ?? throw new InvalidOperationException("CancelScanHandler not provided"));
    }

    // ------------------------------------------------------------------
    // Progress coalescing — apply multiple updates
    // ------------------------------------------------------------------

    [Fact]
    public void ApplyProgress_updates_all_fields()
    {
        var vm = CreateViewModel();

        var progress = new ScanProgress(
            Stage: ScanStage.Running,
            DiscoveredFiles: 100,
            ProcessedFiles: 42,
            FailedFiles: 2,
            PlannedBytes: 1024 * 1024,
            ProcessedBytes: 512 * 1024,
            ArchiveEntryCount: 3,
            FindingCount: 7,
            LlmQueueCount: 5,
            ActiveWorkerCount: 4,
            CurrentFileOrdinal: 42);

        vm.ApplyProgress(progress);

        Assert.Equal(ScanStage.Running, vm.Stage);
        Assert.Equal(100, vm.DiscoveredFiles);
        Assert.Equal(42, vm.ProcessedFiles);
        Assert.Equal(2, vm.FailedFiles);
        Assert.Equal(1024 * 1024, vm.PlannedBytes);
        Assert.Equal(512 * 1024, vm.ProcessedBytes);
        Assert.Equal(3, vm.ArchiveEntryCount);
        Assert.Equal(7, vm.FindingCount);
        Assert.Equal(5, vm.LlmQueueCount);
        Assert.Equal(4, vm.ActiveWorkerCount);
        Assert.Equal(42, vm.CurrentFileOrdinal);
        Assert.Single(vm.StageLog);
    }

    [Fact]
    public void ApplyProgress_calculates_percentage()
    {
        var vm = CreateViewModel();
        vm.ApplyProgress(ScanProgress.Empty with
        {
            Stage = ScanStage.Running,
            DiscoveredFiles = 200,
            ProcessedFiles = 50
        });

        Assert.Equal(25.0, vm.ProgressPercentage);
    }

    [Fact]
    public void ProgressPercentage_is_zero_when_no_files()
    {
        var vm = CreateViewModel();
        Assert.Equal(0.0, vm.ProgressPercentage);
    }

    // ------------------------------------------------------------------
    // Stage display text
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(ScanStage.Draft, "草稿")]
    [InlineData(ScanStage.Preflight, "预检")]
    [InlineData(ScanStage.Inventory, "清单")]
    [InlineData(ScanStage.Running, "扫描中")]
    [InlineData(ScanStage.Reconciling, "协调中")]
    [InlineData(ScanStage.Completed, "已完成")]
    [InlineData(ScanStage.Partial, "部分完成")]
    [InlineData(ScanStage.Cancelled, "已取消")]
    [InlineData(ScanStage.Failed, "已失败")]
    [InlineData(ScanStage.Interrupted, "已中断")]
    public void StageDisplay_shows_correct_chinese_text(ScanStage stage, string expected)
    {
        var vm = CreateViewModel();
        vm.ApplyProgress(ScanProgress.Empty with { Stage = stage });
        Assert.Equal(expected, vm.StageDisplay);
    }

    // ------------------------------------------------------------------
    // Cancel idempotent — disables immediately, shows "正在停止新任务"
    // ------------------------------------------------------------------

    [Fact]
    public void Cancel_disables_button_and_shows_stopping_text()
    {
        var vm = CreateViewModel();
        vm.ScanId = Guid.NewGuid().ToString();
        Assert.True(vm.CancelEnabled);
        Assert.Equal("取消扫描", vm.CancelButtonText);

        vm.MarkCancelling();

        Assert.False(vm.CancelEnabled);
        Assert.Equal("正在停止新任务", vm.CancelButtonText);
        Assert.True(vm.IsCancelling);
    }

    [Fact]
    public void MarkCancelling_is_idempotent()
    {
        var vm = CreateViewModel();

        vm.MarkCancelling();
        vm.MarkCancelling();

        Assert.True(vm.IsCancelling);
        Assert.False(vm.CancelEnabled);
        Assert.Equal("正在停止新任务", vm.CancelButtonText);
    }

    // ------------------------------------------------------------------
    // Terminal state detection
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(ScanStage.Completed, true)]
    [InlineData(ScanStage.Partial, true)]
    [InlineData(ScanStage.Cancelled, true)]
    [InlineData(ScanStage.Failed, true)]
    [InlineData(ScanStage.Interrupted, true)]
    [InlineData(ScanStage.Running, false)]
    [InlineData(ScanStage.Draft, false)]
    [InlineData(ScanStage.Preflight, false)]
    [InlineData(ScanStage.Inventory, false)]
    [InlineData(ScanStage.Reconciling, false)]
    public void IsTerminal_reflects_stage(ScanStage stage, bool expected)
    {
        var vm = CreateViewModel();
        vm.ApplyProgress(ScanProgress.Empty with { Stage = stage });
        Assert.Equal(expected, vm.IsTerminal);
    }

    // ------------------------------------------------------------------
    // Terminal state disables cancel
    // ------------------------------------------------------------------

    [Fact]
    public void Terminal_stage_disables_cancel()
    {
        var vm = CreateViewModel();
        Assert.True(vm.CancelEnabled);

        vm.ApplyProgress(ScanProgress.Empty with { Stage = ScanStage.Completed });

        Assert.False(vm.CancelEnabled);
        Assert.Equal("已完成", vm.CancelButtonText);
    }

    // ------------------------------------------------------------------
    // Progress log
    // ------------------------------------------------------------------

    [Fact]
    public void StageLog_records_each_progress_update()
    {
        var vm = CreateViewModel();
        vm.ApplyProgress(ScanProgress.Empty with { Stage = ScanStage.Preflight });
        vm.ApplyProgress(ScanProgress.Empty with
        {
            Stage = ScanStage.Running,
            DiscoveredFiles = 10,
            ProcessedFiles = 3
        });
        vm.ApplyProgress(ScanProgress.Empty with { Stage = ScanStage.Completed });

        Assert.Equal(3, vm.StageLog.Count);
        Assert.Equal(ScanStage.Preflight, vm.StageLog[0].Stage);
        Assert.Equal(ScanStage.Running, vm.StageLog[1].Stage);
        Assert.Equal(ScanStage.Completed, vm.StageLog[2].Stage);
    }

    // ------------------------------------------------------------------
    // PropertyChanged
    // ------------------------------------------------------------------

    [Fact]
    public void ApplyProgress_raises_property_changed()
    {
        var vm = CreateViewModel();
        var changed = new HashSet<string>();
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is not null)
                changed.Add(e.PropertyName);
        };

        vm.ApplyProgress(ScanProgress.Empty with
        {
            Stage = ScanStage.Running,
            DiscoveredFiles = 1,
            ProcessedFiles = 1,
        });

        Assert.Contains(nameof(ScanProgressViewModel.Stage), changed);
        Assert.Contains(nameof(ScanProgressViewModel.DiscoveredFiles), changed);
        Assert.Contains(nameof(ScanProgressViewModel.ProcessedFiles), changed);
    }

    [Fact]
    public void Implements_INotifyPropertyChanged()
    {
        var vm = CreateViewModel();
        Assert.IsAssignableFrom<INotifyPropertyChanged>(vm);
    }
}
