using System.Collections.ObjectModel;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Desktop.Services;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the coverage/scan-completeness view. Lists coverage gaps
/// with reason, stage, format, redacted virtual path, planned/processed
/// bytes, and help text.
///
/// The header always shows the terminal scan status independently of risk
/// count. Zero/all-covered renders "在本次成功覆盖范围内未发现风险"; any gap
/// renders "扫描不完整" with count and never renders "安全/可发布/无风险保证".
/// </summary>
public sealed class CoverageViewModel : ObservableObject
{
    private readonly IUiErrorSink _errorSink;
    private readonly Func<ScanQueryService> _queryServiceFactory;

    // Scan context
    private ScanId _scanId;
    private ScanStatus _scanStatus;
    private int _totalGaps;
    private int _totalFiles;
    private string _conclusionHeader = "";
    private bool _isComplete;

    // Pagination
    private int _currentGapPage;
    private int _totalGapPages;
    private int _currentFilePage;
    private int _totalFilePages;
    private const int PageSize = 500;

    // Data
    private readonly ObservableCollection<CoverageGapItem> _gaps = new();
    private readonly ObservableCollection<CoverageFileItem> _files = new();

    public CoverageViewModel(
        IUiErrorSink errorSink,
        Func<ScanQueryService> queryServiceFactory)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _queryServiceFactory = queryServiceFactory
            ?? throw new ArgumentNullException(nameof(queryServiceFactory));

        LoadGapsCommand = new AsyncRelayCommand(
            LoadGapsAsync, errorSink);
        LoadFilesCommand = new AsyncRelayCommand(
            LoadFilesAsync, errorSink);
        PreviousGapPageCommand = new AsyncRelayCommand(
            PreviousGapPageAsync, errorSink);
        NextGapPageCommand = new AsyncRelayCommand(
            NextGapPageAsync, errorSink);
        PreviousFilePageCommand = new AsyncRelayCommand(
            PreviousFilePageAsync, errorSink);
        NextFilePageCommand = new AsyncRelayCommand(
            NextFilePageAsync, errorSink);
    }

    // ------------------------------------------------------------------ Commands

    public ICommand LoadGapsCommand { get; }
    public ICommand LoadFilesCommand { get; }
    public ICommand PreviousGapPageCommand { get; }
    public ICommand NextGapPageCommand { get; }
    public ICommand PreviousFilePageCommand { get; }
    public ICommand NextFilePageCommand { get; }

    // ------------------------------------------------------------------ Scan context

    public ScanId ScanId
    {
        get => _scanId;
        set => SetProperty(ref _scanId, value);
    }

    public ScanStatus ScanStatus
    {
        get => _scanStatus;
        set
        {
            if (SetProperty(ref _scanStatus, value))
                UpdateConclusionHeader();
        }
    }

    public string ScanStatusDisplay => _scanStatus switch
    {
        ScanStatus.Completed => "已完成",
        ScanStatus.Partial => "部分完成",
        ScanStatus.Cancelled => "已取消",
        ScanStatus.Failed => "已失败",
        ScanStatus.Interrupted => "已中断",
        ScanStatus.Running => "扫描中",
        _ => _scanStatus.ToString(),
    };

    public int TotalGaps
    {
        get => _totalGaps;
        set
        {
            if (SetProperty(ref _totalGaps, value))
                UpdateConclusionHeader();
        }
    }

    public int TotalFiles
    {
        get => _totalFiles;
        set => SetProperty(ref _totalFiles, value);
    }

    public string ConclusionHeader
    {
        get => _conclusionHeader;
        set => SetProperty(ref _conclusionHeader, value);
    }

    public bool IsComplete
    {
        get => _isComplete;
        set => SetProperty(ref _isComplete, value);
    }

    // ------------------------------------------------------------------ Pagination (gaps)

    public int CurrentGapPage
    {
        get => _currentGapPage;
        set => SetProperty(ref _currentGapPage, value);
    }

    public int TotalGapPages
    {
        get => _totalGapPages;
        set => SetProperty(ref _totalGapPages, value);
    }

    public bool HasPreviousGapPage => _currentGapPage > 1;
    public bool HasNextGapPage => _currentGapPage < _totalGapPages;

    // ------------------------------------------------------------------ Pagination (files)

    public int CurrentFilePage
    {
        get => _currentFilePage;
        set => SetProperty(ref _currentFilePage, value);
    }

    public int TotalFilePages
    {
        get => _totalFilePages;
        set => SetProperty(ref _totalFilePages, value);
    }

    public bool HasPreviousFilePage => _currentFilePage > 1;
    public bool HasNextFilePage => _currentFilePage < _totalFilePages;

    // ------------------------------------------------------------------ Data binding

    public ObservableCollection<CoverageGapItem> Gaps => _gaps;
    public ObservableCollection<CoverageFileItem> Files => _files;

    // ------------------------------------------------------------------ Public API

    /// <summary>
    /// Initializes the view model for a specific scan.
    /// </summary>
    public async Task InitializeAsync(ScanId scanId, CancellationToken cancellationToken)
    {
        _scanId = scanId;
        OnPropertyChanged(nameof(ScanId));

        ScanQueryService query = _queryServiceFactory();
        ScanSummary? summary = await query
            .GetSummaryAsync(scanId, cancellationToken)
            .ConfigureAwait(true);

        if (summary is not null)
        {
            ScanStatus = summary.Status;
            OnPropertyChanged(nameof(ScanStatusDisplay));
            TotalGaps = summary.GapCount;
        }

        await LoadGapsAsync(null, cancellationToken);
    }

    // ------------------------------------------------------------------ Private helpers

    private Task LoadGapsAsync(object? parameter, CancellationToken cancellationToken)
    {
        return LoadGapsAsync(cancellationToken);
    }

    private async Task LoadGapsAsync(CancellationToken cancellationToken)
    {
        ScanQueryService query = _queryServiceFactory();

        PagedResult<CoverageGapSummary> page = await query
            .GetCoveragePagedAsync(
                _scanId,
                (_currentGapPage - 1) * PageSize,
                PageSize,
                cancellationToken)
            .ConfigureAwait(true);

        _gaps.Clear();
        foreach (CoverageGapSummary gap in page.Items)
        {
            _gaps.Add(new CoverageGapItem(
                gap.GapId,
                gap.Stage,
                gap.Reason,
                gap.DetailCode,
                gap.CreatedAtUtc));
        }

        TotalGapPages = page.TotalCount > 0
            ? (int)Math.Ceiling((double)page.TotalCount / PageSize)
            : 1;
        OnPropertyChanged(nameof(HasPreviousGapPage));
        OnPropertyChanged(nameof(HasNextGapPage));
    }

    private Task LoadFilesAsync(object? parameter, CancellationToken cancellationToken)
    {
        return LoadFilesAsync(cancellationToken);
    }

    private async Task LoadFilesAsync(CancellationToken cancellationToken)
    {
        ScanQueryService query = _queryServiceFactory();

        PagedResult<CoverageGapSummary> page = await query
            .GetFilesPagedAsync(
                _scanId,
                (_currentFilePage - 1) * PageSize,
                PageSize,
                cancellationToken)
            .ConfigureAwait(true);

        _files.Clear();
        foreach (CoverageGapSummary file in page.Items)
        {
            _files.Add(new CoverageFileItem(
                file.GapId,
                file.Stage,
                file.Reason,
                file.DetailCode,
                file.CreatedAtUtc));
        }

        TotalFiles = page.TotalCount;
        TotalFilePages = page.TotalCount > 0
            ? (int)Math.Ceiling((double)page.TotalCount / PageSize)
            : 1;
        OnPropertyChanged(nameof(HasPreviousFilePage));
        OnPropertyChanged(nameof(HasNextFilePage));
    }

    private Task PreviousGapPageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentGapPage > 1)
        {
            _currentGapPage--;
            OnPropertyChanged(nameof(CurrentGapPage));
            OnPropertyChanged(nameof(HasPreviousGapPage));
            OnPropertyChanged(nameof(HasNextGapPage));
            return LoadGapsAsync(cancellationToken);
        }
        return Task.CompletedTask;
    }

    private Task NextGapPageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentGapPage < _totalGapPages)
        {
            _currentGapPage++;
            OnPropertyChanged(nameof(CurrentGapPage));
            OnPropertyChanged(nameof(HasPreviousGapPage));
            OnPropertyChanged(nameof(HasNextGapPage));
            return LoadGapsAsync(cancellationToken);
        }
        return Task.CompletedTask;
    }

    private Task PreviousFilePageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentFilePage > 1)
        {
            _currentFilePage--;
            OnPropertyChanged(nameof(CurrentFilePage));
            OnPropertyChanged(nameof(HasPreviousFilePage));
            OnPropertyChanged(nameof(HasNextFilePage));
            return LoadFilesAsync(cancellationToken);
        }
        return Task.CompletedTask;
    }

    private Task NextFilePageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentFilePage < _totalFilePages)
        {
            _currentFilePage++;
            OnPropertyChanged(nameof(CurrentFilePage));
            OnPropertyChanged(nameof(HasPreviousFilePage));
            OnPropertyChanged(nameof(HasNextFilePage));
            return LoadFilesAsync(cancellationToken);
        }
        return Task.CompletedTask;
    }

    private void UpdateConclusionHeader()
    {
        // Header always shows terminal status independently of risk count.
        if (_scanStatus is ScanStatus.Failed or ScanStatus.Interrupted)
        {
            ConclusionHeader = "扫描失败 — 结果不完整。";
            IsComplete = false;
            return;
        }

        if (_scanStatus == ScanStatus.Cancelled)
        {
            ConclusionHeader = "扫描已取消。";
            IsComplete = false;
            return;
        }

        if (_scanStatus == ScanStatus.Running)
        {
            ConclusionHeader = "扫描进行中…";
            IsComplete = false;
            return;
        }

        // Terminal status (Completed, Partial).
        if (_totalGaps == 0)
        {
            ConclusionHeader = "在本次成功覆盖范围内未发现风险。";
            IsComplete = true;
        }
        else
        {
            ConclusionHeader = $"扫描不完整 — {_totalGaps} 个覆盖缺口。";
            IsComplete = false;
        }

        // Never render "安全/可发布/无风险保证".
    }
}

// ---------------------------------------------------------------------------
// Supporting display types
// ---------------------------------------------------------------------------

/// <summary>
/// Display item for a single coverage gap.
/// </summary>
public sealed record CoverageGapItem(
    Guid GapId,
    string Stage,
    GapReason Reason,
    string DetailCode,
    DateTimeOffset CreatedAtUtc)
{
    public string StageDisplay => Stage switch
    {
        "preflight" => "预检",
        "inventory" => "清单",
        "run" => "扫描",
        "semantic_review" => "语义审查",
        "reconciliation" => "协调",
        "file" => "文件",
        _ => Stage,
    };

    public string ReasonDisplay => Reason switch
    {
        GapReason.UnsupportedFormat => "不支持的格式",
        GapReason.UnsupportedRegion => "不支持的区域",
        GapReason.AccessDenied => "访问被拒绝",
        GapReason.Encrypted => "已加密",
        GapReason.DecodeUnreliable => "解码不可靠",
        GapReason.Corrupt => "已损坏",
        GapReason.ArchiveLimit => "归档限制",
        GapReason.ParserTimeout => "解析器超时",
        GapReason.ParserMemory => "解析器内存不足",
        GapReason.ParserCrash => "解析器崩溃",
        GapReason.SandboxUnavailable => "沙箱不可用",
        GapReason.FileUnstable => "文件不稳定",
        GapReason.UserExcluded => "用户排除",
        GapReason.LlmUnresolved => "LLM 未解析",
        GapReason.Cancelled => "已取消",
        GapReason.DiskFull => "磁盘已满",
        GapReason.UnexpectedGitMetadata => "Git 元数据",
        GapReason.ParserProtocolMismatch => "解析器协议不匹配",
        _ => Reason.ToString(),
    };

    public string HelpText => Reason switch
    {
        GapReason.UnsupportedFormat => "文件格式当前不可解析。可向团队提交格式支持需求。",
        GapReason.AccessDenied => "应用没有此文件的读取权限。请检查文件权限或排除路径。",
        GapReason.Encrypted => "文件已加密且无法解密。请在解密后重新扫描或排除此文件。",
        GapReason.UserExcluded => "用户已手动排除此路径。可在扫描设置中调整排除列表。",
        GapReason.LlmUnresolved => "语义审查未能完成。可稍后重试语义审查。",
        GapReason.Cancelled => "扫描已在用户或系统干预下取消。",
        _ => "此文件无法完整扫描。请检查相关日志获取更多信息。",
    };
}

/// <summary>
/// Display item for a single file in the coverage view.
/// </summary>
public sealed record CoverageFileItem(
    Guid FileEntryId,
    string Stage,
    GapReason Reason,
    string DetailCode,
    DateTimeOffset CreatedAtUtc)
{
    public string RedactedPath => DetailCode.Length > 40
        ? DetailCode[..40] + "..."
        : DetailCode;

    public string ReasonDisplay => Reason switch
    {
        GapReason.UnsupportedFormat => "不支持的格式",
        GapReason.AccessDenied => "访问被拒绝",
        GapReason.Encrypted => "已加密",
        GapReason.Corrupt => "已损坏",
        _ => Reason.ToString(),
    };
}
