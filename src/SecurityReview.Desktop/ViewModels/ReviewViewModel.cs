using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.Reviews;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using ReviewsReviewStatus = SecurityReview.Domain.Reviews.ReviewStatus;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the review decision UX.
/// Buttons: ConfirmedRisk, FalsePositive, ApprovedException, RemediatedAwaitingRescan.
/// Reason required. Exception requires binding summary + expiry.
/// Show identity/time + append-only timeline. No global whitelist.
/// </summary>
public sealed class ReviewViewModel : ObservableObject
{
    private readonly IReviewService _reviewService;
    private readonly IUiErrorSink _errorSink;

    // Current context
    private ScanId _scanId;
    private FindingGroupId? _groupId;
    private FindingOccurrenceId? _occurrenceId;
    private bool _hasSelection;

    // Review state
    private ReviewsReviewStatus _selectedStatus = ReviewsReviewStatus.ConfirmedRisk;
    private string _reason = "";
    private string _reasonCode = "";
    private DateTimeOffset _exceptionExpiry = DateTimeOffset.UtcNow.AddDays(90);
    private bool _isSubmitting;

    // Timeline
    private ObservableCollection<ReviewTimelineEntry> _timeline = new();

    // Exception binding fields
    private string _exceptionAssetId = "";
    private string _exceptionAssetVersion = "";
    private string _exceptionFilePath = "";
    private string _exceptionLocator = "";
    private string _exceptionFindingValue = "";
    private string _exceptionRulePackHash = "";
    private string _exceptionRuleId = "";

    // Current user info
    private string _currentUser = "";
    private string _currentTime = "";

    public ReviewViewModel(IReviewService reviewService, IUiErrorSink errorSink)
    {
        _reviewService = reviewService;
        _errorSink = errorSink;

        SubmitReviewCommand = new RelayCommand(_ => SubmitReview(), _ => HasSelection && !IsSubmitting && !string.IsNullOrWhiteSpace(Reason));

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(HasSelection) or nameof(IsSubmitting) or nameof(Reason))
                CommandManager.InvalidateRequerySuggested();
        };

        _exceptionExpiry = DateTimeOffset.UtcNow.AddDays(90);
    }

    // ------------------------------------------------------------------ Commands

    public ICommand SubmitReviewCommand { get; }

    // ------------------------------------------------------------------ Properties

    public bool HasSelection
    {
        get => _hasSelection;
        set => SetProperty(ref _hasSelection, value);
    }

    public ReviewsReviewStatus SelectedStatus
    {
        get => _selectedStatus;
        set
        {
            if (SetProperty(ref _selectedStatus, value))
                OnPropertyChanged(nameof(IsExceptionStatus));
        }
    }

    public string Reason
    {
        get => _reason;
        set => SetProperty(ref _reason, value);
    }

    public string ReasonCode
    {
        get => _reasonCode;
        set => SetProperty(ref _reasonCode, value);
    }

    public DateTimeOffset ExceptionExpiry
    {
        get => _exceptionExpiry;
        set => SetProperty(ref _exceptionExpiry, value);
    }

    public bool IsSubmitting
    {
        get => _isSubmitting;
        set => SetProperty(ref _isSubmitting, value);
    }

    public bool IsExceptionStatus => _selectedStatus == ReviewsReviewStatus.ApprovedException;

    public ObservableCollection<ReviewTimelineEntry> Timeline
    {
        get => _timeline;
        set => SetProperty(ref _timeline, value);
    }

    public string CurrentUser
    {
        get => _currentUser;
        set => SetProperty(ref _currentUser, value);
    }

    public string CurrentTime
    {
        get => _currentTime;
        set => SetProperty(ref _currentTime, value);
    }

    // Exception binding fields
    public string ExceptionAssetId
    {
        get => _exceptionAssetId;
        set => SetProperty(ref _exceptionAssetId, value);
    }

    public string ExceptionAssetVersion
    {
        get => _exceptionAssetVersion;
        set => SetProperty(ref _exceptionAssetVersion, value);
    }

    public string ExceptionFilePath
    {
        get => _exceptionFilePath;
        set => SetProperty(ref _exceptionFilePath, value);
    }

    public string ExceptionLocator
    {
        get => _exceptionLocator;
        set => SetProperty(ref _exceptionLocator, value);
    }

    public string ExceptionFindingValue
    {
        get => _exceptionFindingValue;
        set => SetProperty(ref _exceptionFindingValue, value);
    }

    public string ExceptionRulePackHash
    {
        get => _exceptionRulePackHash;
        set => SetProperty(ref _exceptionRulePackHash, value);
    }

    public string ExceptionRuleId
    {
        get => _exceptionRuleId;
        set => SetProperty(ref _exceptionRuleId, value);
    }

    // ------------------------------------------------------------------ Selection

    /// <summary>
    /// Set the current selection context for review.
    /// </summary>
    public void SetSelection(ScanId scanId, FindingGroupId? groupId, FindingOccurrenceId? occurrenceId)
    {
        _scanId = scanId;
        _groupId = groupId;
        _occurrenceId = occurrenceId;
        HasSelection = occurrenceId is not null || groupId is not null;
        CurrentTime = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        CurrentUser = Environment.UserName;
    }

    /// <summary>
    /// Load timeline for the current selection.
    /// </summary>
    public void LoadTimeline(IReadOnlyList<ReviewDecision> decisions)
    {
        _timeline.Clear();
        foreach (var d in decisions.OrderBy(d => d.DecidedAtUtc))
        {
            _timeline.Add(new ReviewTimelineEntry(
                d.Id,
                d.Status,
                d.ReasonCode,
                d.DecidedAtUtc));
        }
    }

    // ------------------------------------------------------------------ Submit

    private async void SubmitReview()
    {
        if (!HasSelection) return;
        if (string.IsNullOrWhiteSpace(Reason))
        {
            MessageBox.Show("请提供复核理由。", "复核", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        IsSubmitting = true;
        try
        {
            if (_selectedStatus == ReviewsReviewStatus.ApprovedException)
            {
                await SubmitExceptionAsync();
            }
            else
            {
                await SubmitDecisionAsync();
            }
        }
        catch (Exception)
        {
            _errorSink.Report("review_submit_failed", $"提交复核失败。");
        }
        finally
        {
            IsSubmitting = false;
        }
    }

    private async Task SubmitDecisionAsync()
    {
        var command = new RecordReviewCommand(
            _scanId,
            _groupId,
            _occurrenceId,
            _selectedStatus,
            string.IsNullOrWhiteSpace(_reasonCode) ? "manual_review" : _reasonCode,
            _reason);

        var decision = await _reviewService.RecordReviewAsync(command);
        _timeline.Add(new ReviewTimelineEntry(
            decision.Id, decision.Status, decision.ReasonCode, decision.DecidedAtUtc));

        MessageBox.Show("复核已记录。", "复核", MessageBoxButton.OK, MessageBoxImage.Information);
        Reason = "";
        ReasonCode = "";
    }

    private async Task SubmitExceptionAsync()
    {
        if (_exceptionExpiry <= DateTimeOffset.UtcNow)
        {
            MessageBox.Show("例外有效期必须为将来的时间。", "例外", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var command = new GrantExceptionCommand(
            _scanId,
            _occurrenceId ?? throw new InvalidOperationException("例外必须针对具体发现出现。"),
            _exceptionAssetId,
            _exceptionAssetVersion,
            _exceptionFilePath,
            _exceptionLocator,
            _exceptionFindingValue,
            _exceptionRulePackHash,
            _exceptionRuleId,
            _exceptionExpiry,
            _reason);

        var grant = await _reviewService.GrantExceptionAsync(command);

        _timeline.Add(new ReviewTimelineEntry(
            new DecisionId(Guid.NewGuid()),
            ReviewsReviewStatus.ApprovedException,
            "exception_granted",
            DateTimeOffset.UtcNow));

        MessageBox.Show($"例外已授予，有效期至 {_exceptionExpiry:yyyy-MM-dd}。\n\n" +
                        $"绑定摘要:\n资产: {TruncateId(_exceptionAssetId)}\n" +
                        $"规则: {_exceptionRuleId}",
            "例外", MessageBoxButton.OK, MessageBoxImage.Information);

        Reason = "";
        ReasonCode = "";
    }

    private static string TruncateId(string id)
    {
        if (string.IsNullOrEmpty(id)) return "[空]";
        return id.Length > 16 ? id[..16] + "…" : id;
    }
}

// ---------------------------------------------------------------------------
// Timeline entry type
// ---------------------------------------------------------------------------

public sealed record ReviewTimelineEntry(
    DecisionId DecisionId,
    ReviewsReviewStatus Status,
    string ReasonCode,
    DateTimeOffset DecidedAtUtc)
{
    public string StatusDisplay => Status switch
    {
        ReviewsReviewStatus.Pending => "待复核",
        ReviewsReviewStatus.ConfirmedRisk => "确认为风险",
        ReviewsReviewStatus.FalsePositive => "误报",
        ReviewsReviewStatus.ApprovedException => "已批准例外",
        ReviewsReviewStatus.RemediatedAwaitingRescan => "已修复 (等待重新扫描)",
        _ => Status.ToString()
    };

    public string DecidedAtDisplay => DecidedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}

// ---------------------------------------------------------------------------
// Simple synchronous relay command
// ---------------------------------------------------------------------------

file sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
}
