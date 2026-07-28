using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.History;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the scan history list.
/// Shows scan time/status/asset/rule/client/input hash/risk/gap counts.
/// Rescan = new scan with diff filters. Never edits old scan.
/// Deletion shows irreversible scope.
/// </summary>
public sealed class HistoryViewModel : ObservableObject
{
    private readonly Func<ScanQueryService> _queryFactory;
    private readonly Func<RescanHandler> _rescanFactory;
    private readonly Func<RetentionService> _retentionFactory;
    private readonly IUiErrorSink _errorSink;

    private ObservableCollection<ScanHistoryItem> _scans = new();
    private ScanHistoryItem? _selectedScan;
    private bool _isLoading;

    private const int DefaultPageSize = 50;

    public HistoryViewModel(
        Func<ScanQueryService> queryFactory,
        Func<RescanHandler> rescanFactory,
        Func<RetentionService> retentionFactory,
        IUiErrorSink errorSink)
    {
        _queryFactory = queryFactory;
        _rescanFactory = rescanFactory;
        _retentionFactory = retentionFactory;
        _errorSink = errorSink;

        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), errorSink);
        ViewScanCommand = new AsyncRelayCommand(
            ViewScanAsync, errorSink,
            parameter => ResolveScan(parameter) is not null && !IsLoading);
        RescanCommand = new AsyncRelayCommand(_ => RescanSelectedAsync(), errorSink,
            _ => SelectedScan is not null && !IsLoading);
        DeleteCommand = new AsyncRelayCommand(_ => DeleteSelectedAsync(), errorSink,
            _ => SelectedScan is not null && !IsLoading);

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(SelectedScan) or nameof(IsLoading))
                CommandManager.InvalidateRequerySuggested();
        };
    }

    // ------------------------------------------------------------------ Commands

    public ICommand RefreshCommand { get; }
    public ICommand ViewScanCommand { get; }
    public ICommand RescanCommand { get; }
    public ICommand DeleteCommand { get; }

    public event Func<ScanId, CancellationToken, Task>? ScanViewRequested;

    // ------------------------------------------------------------------ Properties

    public ObservableCollection<ScanHistoryItem> Scans
    {
        get => _scans;
        set => SetProperty(ref _scans, value);
    }

    public ScanHistoryItem? SelectedScan
    {
        get => _selectedScan;
        set => SetProperty(ref _selectedScan, value);
    }

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    // ------------------------------------------------------------------ Data loading

    public async Task RefreshAsync(CancellationToken ct = default)
    {
        IsLoading = true;
        try
        {
            var query = _queryFactory();
            var entries = await query.ListScansAsync(DefaultPageSize, 0, ct).ConfigureAwait(true);

            var items = new List<ScanHistoryItem>();
            foreach (var entry in entries)
            {
                var summary = await query.GetSummaryAsync(entry.ScanId, ct).ConfigureAwait(true);
                items.Add(new ScanHistoryItem(
                    entry.ScanId,
                    entry.Status,
                    entry.CreatedAtUtc,
                    entry.UpdatedAtUtc,
                    entry.RulePackFingerprint.Length >= 8 ? entry.RulePackFingerprint[..8] : entry.RulePackFingerprint,
                    entry.EndpointFingerprint.Length >= 8 ? entry.EndpointFingerprint[..8] : entry.EndpointFingerprint,
                    entry.PipelineFingerprint.Length >= 8 ? entry.PipelineFingerprint[..8] : entry.PipelineFingerprint,
                    summary?.GroupCount ?? 0,
                    summary?.OccurrenceCount ?? 0,
                    summary?.GapCount ?? 0));
            }

            _scans.Clear();
            foreach (var item in items)
                _scans.Add(item);
        }
        catch (Exception)
        {
            _errorSink.Report("history_load_failed", $"加载扫描历史失败。");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ViewScanAsync(
        object? parameter,
        CancellationToken cancellationToken)
    {
        ScanHistoryItem? scan = ResolveScan(parameter);
        if (scan is null)
            return;

        SelectedScan = scan;
        if (ScanViewRequested is null)
        {
            _errorSink.Report(
                "history_view_unavailable",
                "扫描回放服务未连接，请重新启动应用后重试。");
            return;
        }

        await ScanViewRequested(scan.ScanId, cancellationToken)
            .ConfigureAwait(true);
    }

    private ScanHistoryItem? ResolveScan(object? parameter) =>
        parameter as ScanHistoryItem ?? SelectedScan;

    private async Task RescanSelectedAsync()
    {
        if (_selectedScan is null) return;

        var result = MessageBox.Show(
            $"将对当前配置执行重新扫描。\n\n" +
            $"重新扫描将创建新的扫描，并与之前的扫描 ({_selectedScan.CreatedAtDisplay}) 进行比较。\n" +
            $"结果可按以下状态筛选：新增 / 持续存在 / 已解决 / 重新出现 / 无法复核。\n\n" +
            $"上一个扫描不会被修改。是否继续？",
            "重新扫描",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            var rescan = _rescanFactory();
            // The setup view owns the current target/configuration inputs. Keep
            // historical rows immutable and direct the user there before a new run.
            MessageBox.Show(
                "请在「新建扫描」页面配置扫描目标后执行重新扫描。\n\n" +
                "系统将自动与上一个扫描进行对比。",
                "重新扫描",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception)
        {
            _errorSink.Report("rescan_failed", $"重新扫描启动失败。");
        }
    }

    private async Task DeleteSelectedAsync()
    {
        if (_selectedScan is null) return;

        var scan = _selectedScan;
        var result = MessageBox.Show(
            $"即将删除扫描 {scan.CreatedAtDisplay} 及其所有相关数据。\n\n" +
            $"此操作不可逆。删除的内容包括：\n" +
            $"- 扫描记录和状态\n" +
            $"- 所有发现和复核记录\n" +
            $"- 覆盖率数据\n\n" +
            $"此操作仅影响本机数据，不会影响其他设备。\n\n" +
            $"确定要删除吗？",
            "删除扫描",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            RetentionService retention = _retentionFactory();
            bool deleted = await retention
                .DeleteScanAsync(scan.ScanId)
                .ConfigureAwait(true);
            if (!deleted)
            {
                _errorSink.Report("delete_failed", "扫描记录不存在或已被删除。");
                await RefreshAsync().ConfigureAwait(true);
                return;
            }

            _scans.Remove(scan);
            SelectedScan = null;

            MessageBox.Show("扫描已删除。", "删除", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception)
        {
            _errorSink.Report("delete_failed", $"删除扫描失败。");
        }
    }
}

// ---------------------------------------------------------------------------
// Scan history display item
// ---------------------------------------------------------------------------

public sealed record ScanHistoryItem(
    ScanId ScanId,
    ScanStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string RulePackPrefix,
    string ClientFingerprintPrefix,
    string InputHashPrefix,
    int RiskCount,
    int OccurrenceCount,
    int GapCount)
{
    public string StatusDisplay => Status switch
    {
        ScanStatus.Completed => "已完成",
        ScanStatus.Partial => "部分完成",
        ScanStatus.Cancelled => "已取消",
        ScanStatus.Failed => "失败",
        ScanStatus.Interrupted => "中断",
        ScanStatus.Running => "运行中",
        ScanStatus.Cancelling => "正在取消",
        _ => Status.ToString()
    };

    public string CreatedAtDisplay => CreatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public string UpdatedAtDisplay => UpdatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public string RiskSummary => $"风险: {RiskCount} | 出现: {OccurrenceCount} | 覆盖缺口: {GapCount}";
}
