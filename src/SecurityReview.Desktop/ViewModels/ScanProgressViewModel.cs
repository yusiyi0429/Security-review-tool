using System.Collections.ObjectModel;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the live scan progress view. Binds to the orchestrator's
/// progress stream, showing stage/discovered/processed/failed counts, bytes,
/// archive entries, active workers, finding count, and LLM queue.
///
/// Never exposes raw paths or content — only ordinals and types.
/// Cancel is idempotent: once clicked, the button disables and shows
/// "正在停止新任务" until the terminal Cancelled state arrives.
/// </summary>
public sealed class ScanProgressViewModel : ObservableObject, IDisposable
{
    private readonly IUiErrorSink _errorSink;
    private readonly Func<CancelScanHandler> _cancelScanHandlerFactory;

    private string _scanId = "";
    private ScanStage _stage = ScanStage.Draft;
    private int _discoveredFiles;
    private int _processedFiles;
    private int _failedFiles;
    private long _plannedBytes;
    private long _processedBytes;
    private int _archiveEntryCount;
    private int _findingCount;
    private int _llmQueueCount;
    private int _activeWorkerCount;
    private int _currentFileOrdinal;
    private bool _isCancelling;
    private bool _cancelRequested;
    private string _cancelButtonText = "取消扫描";
    private bool _cancelEnabled = true;

    private readonly ObservableCollection<ProgressStageItem> _stageLog = new();

    public ScanProgressViewModel(
        IUiErrorSink errorSink,
        Func<CancelScanHandler> cancelScanHandlerFactory)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _cancelScanHandlerFactory = cancelScanHandlerFactory
            ?? throw new ArgumentNullException(nameof(cancelScanHandlerFactory));

        CancelCommand = new AsyncRelayCommand(
            CancelAsync, errorSink);
    }

    // ------------------------------------------------------------------ Commands

    public ICommand CancelCommand { get; }

    // ------------------------------------------------------------------ Progress properties

    public string ScanId
    {
        get => _scanId;
        set => SetProperty(ref _scanId, value);
    }

    public ScanStage Stage
    {
        get => _stage;
        set => SetProperty(ref _stage, value);
    }

    public string StageDisplay => _stage switch
    {
        ScanStage.Draft => "草稿",
        ScanStage.Preflight => "预检",
        ScanStage.Inventory => "清单",
        ScanStage.Running => "扫描中",
        ScanStage.Reconciling => "协调中",
        ScanStage.Completed => "已完成",
        ScanStage.Partial => "部分完成",
        ScanStage.Cancelled => "已取消",
        ScanStage.Failed => "已失败",
        ScanStage.Interrupted => "已中断",
        _ => "未知",
    };

    public int DiscoveredFiles
    {
        get => _discoveredFiles;
        set => SetProperty(ref _discoveredFiles, value);
    }

    public int ProcessedFiles
    {
        get => _processedFiles;
        set => SetProperty(ref _processedFiles, value);
    }

    public int FailedFiles
    {
        get => _failedFiles;
        set => SetProperty(ref _failedFiles, value);
    }

    public long PlannedBytes
    {
        get => _plannedBytes;
        set => SetProperty(ref _plannedBytes, value);
    }

    public long ProcessedBytes
    {
        get => _processedBytes;
        set => SetProperty(ref _processedBytes, value);
    }

    public int ArchiveEntryCount
    {
        get => _archiveEntryCount;
        set => SetProperty(ref _archiveEntryCount, value);
    }

    public int FindingCount
    {
        get => _findingCount;
        set => SetProperty(ref _findingCount, value);
    }

    public int LlmQueueCount
    {
        get => _llmQueueCount;
        set => SetProperty(ref _llmQueueCount, value);
    }

    public int ActiveWorkerCount
    {
        get => _activeWorkerCount;
        set => SetProperty(ref _activeWorkerCount, value);
    }

    public int CurrentFileOrdinal
    {
        get => _currentFileOrdinal;
        set => SetProperty(ref _currentFileOrdinal, value);
    }

    // ------------------------------------------------------------------ Cancel state

    public bool IsCancelling
    {
        get => _isCancelling;
        set => SetProperty(ref _isCancelling, value);
    }

    public bool CancelRequested
    {
        get => _cancelRequested;
        set
        {
            if (SetProperty(ref _cancelRequested, value))
                OnPropertyChanged(nameof(CancelButtonText));
        }
    }

    public string CancelButtonText
    {
        get => _cancelButtonText;
        set => SetProperty(ref _cancelButtonText, value);
    }

    public bool CancelEnabled
    {
        get => _cancelEnabled;
        set => SetProperty(ref _cancelEnabled, value);
    }

    // ------------------------------------------------------------------ Stage log

    public ObservableCollection<ProgressStageItem> StageLog => _stageLog;

    // ------------------------------------------------------------------ Progress percentage

    public double ProgressPercentage => _discoveredFiles > 0
        ? Math.Min(100.0, (double)_processedFiles / _discoveredFiles * 100.0)
        : 0.0;

    /// <summary>Whether the scan has reached a terminal stage.</summary>
    public bool IsTerminal => _stage is ScanStage.Completed or ScanStage.Partial
        or ScanStage.Cancelled or ScanStage.Failed or ScanStage.Interrupted;

    // ------------------------------------------------------------------ Public API

    /// <summary>
    /// Applies a progress update from the orchestrator stream.
    /// </summary>
    public void ApplyProgress(ScanProgress progress)
    {
        Stage = progress.Stage;
        DiscoveredFiles = progress.DiscoveredFiles;
        ProcessedFiles = progress.ProcessedFiles;
        FailedFiles = progress.FailedFiles;
        PlannedBytes = progress.PlannedBytes;
        ProcessedBytes = progress.ProcessedBytes;
        ArchiveEntryCount = progress.ArchiveEntryCount;
        FindingCount = progress.FindingCount;
        LlmQueueCount = progress.LlmQueueCount;
        ActiveWorkerCount = progress.ActiveWorkerCount;
        CurrentFileOrdinal = progress.CurrentFileOrdinal;

        OnPropertyChanged(nameof(StageDisplay));
        OnPropertyChanged(nameof(ProgressPercentage));
        OnPropertyChanged(nameof(IsTerminal));

        _stageLog.Add(new ProgressStageItem(
            progress.Stage,
            $"已发现: {progress.DiscoveredFiles}, " +
            $"已处理: {progress.ProcessedFiles}, " +
            $"发现: {progress.FindingCount}"));

        // If terminal, disable cancel.
        if (IsTerminal)
        {
            CancelEnabled = false;
            CancelButtonText = "已完成";
        }
    }

    /// <summary>
    /// Marks the scan as cancelling — disables the cancel button and
    /// updates the display text.
    /// </summary>
    public void MarkCancelling()
    {
        IsCancelling = true;
        CancelEnabled = false;
        CancelButtonText = "正在停止新任务";
    }

    public void Dispose()
    {
        // Clean up any subscriptions.
    }

    // ------------------------------------------------------------------ Private

    private async Task CancelAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (IsCancelling)
            return;

        MarkCancelling();

        try
        {
            CancelScanHandler handler = _cancelScanHandlerFactory();
            bool cancelled = await handler.HandleAsync(
                new Domain.ScanId(Guid.Parse(_scanId)),
                cancellationToken)
                .ConfigureAwait(true);

            if (!cancelled)
            {
                // Scan may already be terminal.
                CancelButtonText = "已完成";
            }
        }
        catch (Exception ex)
        {
            string message = AsyncRelayCommand.SanitizeMessage(ex);
            _errorSink.Report("cancel_scan_error", message);
        }
    }
}

/// <summary>
/// A single logged stage transition for the progress view.
/// </summary>
public sealed record ProgressStageItem(ScanStage Stage, string Description);
