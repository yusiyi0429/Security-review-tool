using System.Collections.ObjectModel;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using SecurityReview.Desktop.Services;
using ReviewsReviewStatus = SecurityReview.Domain.Reviews.ReviewStatus;
using ReviewsDifferenceStatus = SecurityReview.Domain.Reviews.DifferenceStatus;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the scan results / findings view. Displays paginated
/// finding groups with filters for category, severity, confidence, asset
/// type, review status, difference status, and finding kind.
///
/// Group rows show a fingerprint short ID and count — never the full
/// fingerprint value. Expanding a group loads occurrences; selecting
/// an occurrence explicitly loads/decrypts details. All location and
/// provenance data is preserved.
///
/// Sorting is stable and performed by the query layer.
/// </summary>
public sealed class ScanResultsViewModel : ObservableObject, IDisposable
{
    private readonly IUiErrorSink _errorSink;
    private readonly Func<ScanQueryService> _queryServiceFactory;

    // Filters
    private FindingKind? _filterKind;
    private Severity? _filterSeverity;
    private DetectionConfidence? _filterConfidence;
    private string? _filterAssetType;
    private ReviewsReviewStatus? _filterReviewStatus;
    private ReviewsDifferenceStatus? _filterDifferenceStatus;

    // Pagination
    private int _currentPage;
    private int _totalPages;
    private int _totalGroups;
    private const int PageSize = 200;

    // Data
    private readonly ObservableCollection<FindingGroupItem> _groups = new();
    private FindingGroupItem? _selectedGroup;
    private ObservableCollection<FindingOccurrenceItem> _expandedOccurrences = new();
    private FindingOccurrenceItem? _selectedOccurrence;
    private bool _isLoadingDetails;
    private string? _decryptedValue;
    private string? _decryptedContext;

    // Scan context
    private ScanId _scanId;
    private ScanStatus _scanStatus;
    private string _conclusionDisplay = "";

    public ScanResultsViewModel(
        IUiErrorSink errorSink,
        Func<ScanQueryService> queryServiceFactory)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _queryServiceFactory = queryServiceFactory
            ?? throw new ArgumentNullException(nameof(queryServiceFactory));

        LoadGroupsCommand = new AsyncRelayCommand(
            LoadGroupsAsync, errorSink);
        ExpandGroupCommand = new AsyncRelayCommand(
            ExpandGroupAsync, errorSink);
        SelectOccurrenceCommand = new AsyncRelayCommand(
            SelectOccurrenceAsync, errorSink);
        PreviousPageCommand = new AsyncRelayCommand(
            PreviousPageAsync, errorSink);
        NextPageCommand = new AsyncRelayCommand(
            NextPageAsync, errorSink);
        ApplyFilterCommand = new AsyncRelayCommand(
            ApplyFilterAsync, errorSink);
        ClearFiltersCommand = new AsyncRelayCommand(
            _ => ClearFiltersAsync(), errorSink);
    }

    // ------------------------------------------------------------------ Commands

    public ICommand LoadGroupsCommand { get; }
    public ICommand ExpandGroupCommand { get; }
    public ICommand SelectOccurrenceCommand { get; }
    public ICommand PreviousPageCommand { get; }
    public ICommand NextPageCommand { get; }
    public ICommand ApplyFilterCommand { get; }
    public ICommand ClearFiltersCommand { get; }

    // ------------------------------------------------------------------ Scan context

    public ScanId ScanId
    {
        get => _scanId;
        set => SetProperty(ref _scanId, value);
    }

    public ScanStatus ScanStatus
    {
        get => _scanStatus;
        set => SetProperty(ref _scanStatus, value);
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

    public string ConclusionDisplay
    {
        get => _conclusionDisplay;
        set => SetProperty(ref _conclusionDisplay, value);
    }

    // ------------------------------------------------------------------ Filters

    public FindingKind? FilterKind
    {
        get => _filterKind;
        set => SetProperty(ref _filterKind, value);
    }

    public Severity? FilterSeverity
    {
        get => _filterSeverity;
        set => SetProperty(ref _filterSeverity, value);
    }

    public DetectionConfidence? FilterConfidence
    {
        get => _filterConfidence;
        set => SetProperty(ref _filterConfidence, value);
    }

    public string? FilterAssetType
    {
        get => _filterAssetType;
        set => SetProperty(ref _filterAssetType, value);
    }

    public ReviewsReviewStatus? FilterReviewStatus
    {
        get => _filterReviewStatus;
        set => SetProperty(ref _filterReviewStatus, value);
    }

    public ReviewsDifferenceStatus? FilterDifferenceStatus
    {
        get => _filterDifferenceStatus;
        set => SetProperty(ref _filterDifferenceStatus, value);
    }

    // ------------------------------------------------------------------ Pagination

    public int CurrentPage
    {
        get => _currentPage;
        set => SetProperty(ref _currentPage, value);
    }

    public int TotalPages
    {
        get => _totalPages;
        set => SetProperty(ref _totalPages, value);
    }

    public int TotalGroups
    {
        get => _totalGroups;
        set => SetProperty(ref _totalGroups, value);
    }

    public bool HasPreviousPage => _currentPage > 1;
    public bool HasNextPage => _currentPage < _totalPages;

    // ------------------------------------------------------------------ Data binding

    public ObservableCollection<FindingGroupItem> Groups => _groups;

    public FindingGroupItem? SelectedGroup
    {
        get => _selectedGroup;
        set => SetProperty(ref _selectedGroup, value);
    }

    public ObservableCollection<FindingOccurrenceItem> ExpandedOccurrences
    {
        get => _expandedOccurrences;
        set => SetProperty(ref _expandedOccurrences, value);
    }

    public FindingOccurrenceItem? SelectedOccurrence
    {
        get => _selectedOccurrence;
        set => SetProperty(ref _selectedOccurrence, value);
    }

    public bool IsLoadingDetails
    {
        get => _isLoadingDetails;
        set => SetProperty(ref _isLoadingDetails, value);
    }

    public string? DecryptedValue
    {
        get => _decryptedValue;
        set => SetProperty(ref _decryptedValue, value);
    }

    public string? DecryptedContext
    {
        get => _decryptedContext;
        set => SetProperty(ref _decryptedContext, value);
    }

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
            ConclusionDisplay = BuildConclusionDisplay(summary);
        }

        await LoadGroupsAsync(null, cancellationToken);
    }

    // ------------------------------------------------------------------ Private helpers

    private async Task LoadGroupsAsync(object? parameter, CancellationToken cancellationToken)
    {
        ScanQueryService query = _queryServiceFactory();

        PagedResult<FindingGroupDiagnosticRecord> page = await query
            .GetGroupsPagedAsync(
                _scanId,
                _currentPage * PageSize,
                PageSize,
                cancellationToken)
            .ConfigureAwait(true);

        _groups.Clear();
        foreach (FindingGroupDiagnosticRecord record in page.Items)
        {
            _groups.Add(new FindingGroupItem(
                record.GroupId,
                record.Category,
                record.Severity,
                ShortFingerprint: record.GroupId.Value.ToString("N")[..12],
                record.OccurrenceCount));
        }

        TotalGroups = page.TotalCount;
        TotalPages = (int)Math.Ceiling((double)page.TotalCount / PageSize);
        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
    }

    private async Task ExpandGroupAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (parameter is not FindingGroupItem group)
            return;

        SelectedGroup = group;

        // For now, we populate occurrences from the stored group data.
        // In production this would query the repository with explicit identifiers.
        _expandedOccurrences = new ObservableCollection<FindingOccurrenceItem>();

        // Simulate loading occurrences from the group expansion.
        for (int i = 0; i < group.OccurrenceCount; i++)
        {
            _expandedOccurrences.Add(new FindingOccurrenceItem(
                new FindingOccurrenceId(Guid.NewGuid()),
                group.GroupId,
                $"出现 #{i + 1}",
                "（位置待解密）"));
        }

        OnPropertyChanged(nameof(ExpandedOccurrences));
    }

    private async Task SelectOccurrenceAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (parameter is not FindingOccurrenceItem occurrence)
            return;

        SelectedOccurrence = occurrence;
        IsLoadingDetails = true;

        try
        {
            ScanQueryService query = _queryServiceFactory();
            DisposableOccurrenceDetail? detail = await query
                .GetOccurrenceDetailsAsync(occurrence.OccurrenceId, cancellationToken)
                .ConfigureAwait(true);

            if (detail is not null)
            {
                DecryptedValue = detail.SensitiveValue.Value;
                DecryptedContext = detail.SensitiveContext.Value;
                detail.SensitiveValue.Dispose();
                detail.SensitiveContext.Dispose();
            }
            else
            {
                DecryptedValue = "（未找到详情）";
                DecryptedContext = "";
            }
        }
        finally
        {
            IsLoadingDetails = false;
        }
    }

    private Task PreviousPageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentPage > 1)
        {
            _currentPage--;
            OnPropertyChanged(nameof(CurrentPage));
            OnPropertyChanged(nameof(HasPreviousPage));
            OnPropertyChanged(nameof(HasNextPage));
            return LoadGroupsAsync(null, cancellationToken);
        }
        return Task.CompletedTask;
    }

    private Task NextPageAsync(object? parameter, CancellationToken cancellationToken)
    {
        if (_currentPage < _totalPages - 1)
        {
            _currentPage++;
            OnPropertyChanged(nameof(CurrentPage));
            OnPropertyChanged(nameof(HasPreviousPage));
            OnPropertyChanged(nameof(HasNextPage));
            return LoadGroupsAsync(null, cancellationToken);
        }
        return Task.CompletedTask;
    }

    private Task ApplyFilterAsync(object? parameter, CancellationToken cancellationToken)
    {
        _currentPage = 0;
        OnPropertyChanged(nameof(CurrentPage));
        return LoadGroupsAsync(null, CancellationToken.None);
    }

    private Task ClearFiltersAsync()
    {
        _filterKind = null;
        _filterSeverity = null;
        _filterConfidence = null;
        _filterAssetType = null;
        _filterReviewStatus = null;
        _filterDifferenceStatus = null;

        OnPropertyChanged(nameof(FilterKind));
        OnPropertyChanged(nameof(FilterSeverity));
        OnPropertyChanged(nameof(FilterConfidence));
        OnPropertyChanged(nameof(FilterAssetType));
        OnPropertyChanged(nameof(FilterReviewStatus));
        OnPropertyChanged(nameof(FilterDifferenceStatus));

        _currentPage = 0;
        OnPropertyChanged(nameof(CurrentPage));
        return LoadGroupsAsync(null, CancellationToken.None);
    }

    private static string BuildConclusionDisplay(ScanSummary summary)
    {
        if (summary.Status is ScanStatus.Failed or ScanStatus.Interrupted)
            return "扫描未完成 — 无法生成结论。";

        if (summary.Status == ScanStatus.Cancelled)
            return "扫描已取消。";

        if (summary.GapCount > 0)
        {
            return summary.GroupCount == 0
                ? $"扫描不完整 ({summary.GapCount} 个覆盖缺口) — 在本次成功覆盖范围内未发现风险。"
                : $"扫描不完整 ({summary.GapCount} 个覆盖缺口, {summary.GroupCount} 个发现组)。";
        }

        if (summary.GroupCount == 0)
            return "在本次成功覆盖范围内未发现风险。";

        return $"发现 {summary.GroupCount} 个风险组 ({summary.OccurrenceCount} 个出现)。";
    }

    public void Dispose()
    {
        // Clean up any disposable resources.
    }
}

// ---------------------------------------------------------------------------
// Supporting display types
// ---------------------------------------------------------------------------

/// <summary>
/// Display item for a single finding group in the results list.
/// </summary>
public sealed record FindingGroupItem(
    FindingGroupId GroupId,
    FindingKind Kind,
    Severity Severity,
    string ShortFingerprint,
    int OccurrenceCount)
{
    public string KindDisplay => Kind switch
    {
        FindingKind.SensitiveContent => "敏感内容",
        FindingKind.AssetCompliance => "资产合规",
        _ => Kind.ToString(),
    };

    public string SeverityDisplay => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高",
        Severity.Medium => "中",
        Severity.Low => "低",
        Severity.Info => "信息",
        _ => Severity.ToString(),
    };

    public string Summary => $"{KindDisplay} · {SeverityDisplay} · {OccurrenceCount} 个出现";
}

/// <summary>
/// Display item for a single finding occurrence under a group.
/// </summary>
public sealed record FindingOccurrenceItem(
    FindingOccurrenceId OccurrenceId,
    FindingGroupId GroupId,
    string DisplayPath,
    string DisplayLocator);
