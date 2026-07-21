using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Input;
using SecurityReview.Application.Reviews;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using ReviewsReviewStatus = SecurityReview.Domain.Reviews.ReviewStatus;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for ReviewViewModel: initial state, selection, timeline loading,
/// status switching, exception visibility, reason/submit validation,
/// and IsSubmitting gating. Does not execute SubmitReviewCommand because
/// the code-behind calls MessageBox.Show which fails in test context.
/// </summary>
public sealed class ReviewViewModelTests
{
    // ------------------------------------------------------------------
    // Stubs
    // ------------------------------------------------------------------

    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();

        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }

    private sealed class TestReviewService : IReviewService
    {
        public List<RecordReviewCommand> RecordedCommands { get; } = new();
        public List<GrantExceptionCommand> ExceptionCommands { get; } = new();

        public ReviewDecision? DecisionToReturn { get; set; }
        public ExceptionGrant? ExceptionToReturn { get; set; }
        public EffectiveReviewResult? EffectiveResultToReturn { get; set; }

        public Task<ReviewDecision> RecordReviewAsync(
            RecordReviewCommand command, CancellationToken ct = default)
        {
            RecordedCommands.Add(command);
            return Task.FromResult(DecisionToReturn!);
        }

        public Task<ExceptionGrant> GrantExceptionAsync(
            GrantExceptionCommand command, CancellationToken ct = default)
        {
            ExceptionCommands.Add(command);
            return Task.FromResult(ExceptionToReturn!);
        }

        public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
            FindingOccurrenceId occurrenceId,
            string assetBindingHmac,
            string occurrenceBindingHmac,
            CancellationToken ct = default)
        {
            return Task.FromResult(EffectiveResultToReturn!);
        }
    }

    // ------------------------------------------------------------------
    // Factory
    // ------------------------------------------------------------------

    private static ReviewViewModel CreateViewModel(
        TestErrorSink? sink = null,
        TestReviewService? service = null)
    {
        sink ??= new TestErrorSink();
        service ??= new TestReviewService();
        return new ReviewViewModel(service, sink);
    }

    // ------------------------------------------------------------------
    // 1. Initial state
    // ------------------------------------------------------------------

    [Fact]
    public void HasSelection_is_false_after_construction()
    {
        var vm = CreateViewModel();
        Assert.False(vm.HasSelection);
    }

    [Fact]
    public void SubmitReviewCommand_cannot_execute_when_no_selection()
    {
        var vm = CreateViewModel();
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Reason_is_empty_after_construction()
    {
        var vm = CreateViewModel();
        Assert.Equal("", vm.Reason);
    }

    [Fact]
    public void IsSubmitting_is_false_after_construction()
    {
        var vm = CreateViewModel();
        Assert.False(vm.IsSubmitting);
    }

    [Fact]
    public void Timeline_is_empty_after_construction()
    {
        var vm = CreateViewModel();
        Assert.Empty(vm.Timeline);
    }

    [Fact]
    public void SelectedStatus_defaults_to_ConfirmedRisk()
    {
        var vm = CreateViewModel();
        Assert.Equal(ReviewsReviewStatus.ConfirmedRisk, vm.SelectedStatus);
    }

    [Fact]
    public void Default_selected_status_means_IsExceptionStatus_is_false()
    {
        var vm = CreateViewModel();
        Assert.False(vm.IsExceptionStatus);
    }

    [Fact]
    public void Implements_INotifyPropertyChanged()
    {
        var vm = CreateViewModel();
        Assert.IsAssignableFrom<INotifyPropertyChanged>(vm);
    }

    // ------------------------------------------------------------------
    // 2. SetSelection
    // ------------------------------------------------------------------

    [Fact]
    public void SetSelection_with_occurrenceId_sets_HasSelection_true()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));

        Assert.True(vm.HasSelection);
    }

    [Fact]
    public void SetSelection_with_groupId_sets_HasSelection_true()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            new FindingGroupId(Guid.NewGuid()),
            null);

        Assert.True(vm.HasSelection);
    }

    [Fact]
    public void SetSelection_with_both_ids_sets_HasSelection_true()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            new FindingGroupId(Guid.NewGuid()),
            new FindingOccurrenceId(Guid.NewGuid()));

        Assert.True(vm.HasSelection);
    }

    [Fact]
    public void SetSelection_with_null_ids_sets_HasSelection_false()
    {
        var vm = CreateViewModel();
        // Force non-null selection first so we can observe it drop to false.
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));

        Assert.True(vm.HasSelection);

        vm.SetSelection(new ScanId(Guid.NewGuid()), null, null);
        Assert.False(vm.HasSelection);
    }

    [Fact]
    public void SetSelection_sets_CurrentUser()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            new FindingGroupId(Guid.NewGuid()),
            null);

        Assert.Equal(Environment.UserName, vm.CurrentUser);
    }

    [Fact]
    public void SetSelection_sets_CurrentTime()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            new FindingGroupId(Guid.NewGuid()),
            null);

        Assert.NotEmpty(vm.CurrentTime);
        // Format: yyyy-MM-dd HH:mm:ss
        Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", vm.CurrentTime);
    }

    [Fact]
    public void SetSelection_enables_submit_when_reason_is_provided()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "确认风险 — 该问题确实存在";

        Assert.True(vm.SubmitReviewCommand.CanExecute(null));
    }

    // ------------------------------------------------------------------
    // 3. LoadTimeline
    // ------------------------------------------------------------------

    [Fact]
    public void LoadTimeline_populates_timeline()
    {
        var vm = CreateViewModel();
        var scanId = new ScanId(Guid.NewGuid());
        var groupId = new FindingGroupId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;

        var decisions = new List<ReviewDecision>
        {
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ConfirmedRisk, "manual_review",
                "risk confirmed", "user-hmac", now.AddHours(-2)),
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.FalsePositive, "manual_review",
                "false positive", "user-hmac", now.AddHours(-1)),
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ApprovedException, "exception_granted",
                "exception", "user-hmac", now),
        };

        vm.LoadTimeline(decisions);

        Assert.Equal(3, vm.Timeline.Count);
    }

    [Fact]
    public void LoadTimeline_entries_are_ordered_by_DecidedAtUtc_ascending()
    {
        var vm = CreateViewModel();
        var scanId = new ScanId(Guid.NewGuid());
        var groupId = new FindingGroupId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;

        var decisions = new List<ReviewDecision>
        {
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ApprovedException, "exception_granted",
                "latest", "user-hmac", now),
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.FalsePositive, "manual_review",
                "middle", "user-hmac", now.AddHours(-1)),
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ConfirmedRisk, "manual_review",
                "earliest", "user-hmac", now.AddHours(-2)),
        };

        vm.LoadTimeline(decisions);

        Assert.Equal(3, vm.Timeline.Count);
        Assert.Equal(ReviewsReviewStatus.ConfirmedRisk, vm.Timeline[0].Status);
        Assert.Equal(ReviewsReviewStatus.FalsePositive, vm.Timeline[1].Status);
        Assert.Equal(ReviewsReviewStatus.ApprovedException, vm.Timeline[2].Status);
    }

    [Fact]
    public void LoadTimeline_clears_previous_entries()
    {
        var vm = CreateViewModel();
        var scanId = new ScanId(Guid.NewGuid());
        var groupId = new FindingGroupId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;

        var firstBatch = new List<ReviewDecision>
        {
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ConfirmedRisk, "manual_review",
                "first", "user-hmac", now),
        };
        vm.LoadTimeline(firstBatch);
        Assert.Single(vm.Timeline);

        var secondBatch = new List<ReviewDecision>
        {
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.FalsePositive, "manual_review",
                "second", "user-hmac", now),
            ReviewDecision.Create(scanId, groupId, null,
                ReviewsReviewStatus.ApprovedException, "exception_granted",
                "third", "user-hmac", now.AddHours(1)),
        };
        vm.LoadTimeline(secondBatch);

        Assert.Equal(2, vm.Timeline.Count);
        Assert.Equal(ReviewsReviewStatus.FalsePositive, vm.Timeline[0].Status);
        Assert.Equal(ReviewsReviewStatus.ApprovedException, vm.Timeline[1].Status);
    }

    [Fact]
    public void ReviewTimelineEntry_StatusDisplay_returns_correct_chinese()
    {
        var now = DateTimeOffset.UtcNow;
        var entry = new ReviewTimelineEntry(
            new DecisionId(Guid.NewGuid()),
            ReviewsReviewStatus.ConfirmedRisk,
            "manual_review",
            now);

        Assert.Equal("确认为风险", entry.StatusDisplay);
    }

    [Theory]
    [InlineData(ReviewsReviewStatus.Pending, "待复核")]
    [InlineData(ReviewsReviewStatus.ConfirmedRisk, "确认为风险")]
    [InlineData(ReviewsReviewStatus.FalsePositive, "误报")]
    [InlineData(ReviewsReviewStatus.ApprovedException, "已批准例外")]
    [InlineData(ReviewsReviewStatus.RemediatedAwaitingRescan, "已修复 (等待重新扫描)")]
    public void ReviewTimelineEntry_StatusDisplay_shows_correct_text_for_each_status(
        ReviewsReviewStatus status, string expected)
    {
        var entry = new ReviewTimelineEntry(
            new DecisionId(Guid.NewGuid()),
            status,
            "manual_review",
            DateTimeOffset.UtcNow);

        Assert.Equal(expected, entry.StatusDisplay);
    }

    [Fact]
    public void ReviewTimelineEntry_DecidedAtDisplay_formats_as_local_time()
    {
        var utcTime = new DateTimeOffset(2025, 6, 15, 8, 30, 0, TimeSpan.Zero);
        var entry = new ReviewTimelineEntry(
            new DecisionId(Guid.NewGuid()),
            ReviewsReviewStatus.ConfirmedRisk,
            "manual_review",
            utcTime);

        var display = entry.DecidedAtDisplay;
        // Should be local time formatted as yyyy-MM-dd HH:mm:ss
        var localTime = utcTime.ToLocalTime();
        var expected = localTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        Assert.Equal(expected, display);
    }

    // ------------------------------------------------------------------
    // 4. Status selection
    // ------------------------------------------------------------------

    [Fact]
    public void SelectedStatus_set_to_ApprovedException_makes_IsExceptionStatus_true()
    {
        var vm = CreateViewModel();
        vm.SelectedStatus = ReviewsReviewStatus.ApprovedException;
        Assert.True(vm.IsExceptionStatus);
    }

    [Theory]
    [InlineData(ReviewsReviewStatus.Pending)]
    [InlineData(ReviewsReviewStatus.ConfirmedRisk)]
    [InlineData(ReviewsReviewStatus.FalsePositive)]
    [InlineData(ReviewsReviewStatus.RemediatedAwaitingRescan)]
    public void IsExceptionStatus_is_false_for_non_exception_statuses(ReviewsReviewStatus status)
    {
        var vm = CreateViewModel();
        vm.SelectedStatus = status;
        Assert.False(vm.IsExceptionStatus);
    }

    [Fact]
    public void SelectedStatus_change_to_exception_status_raises_IsExceptionStatus_notification()
    {
        var vm = CreateViewModel();
        bool isExceptionFired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.IsExceptionStatus))
                isExceptionFired = true;
        };

        vm.SelectedStatus = ReviewsReviewStatus.ApprovedException;
        Assert.True(isExceptionFired);
    }

    [Fact]
    public void SelectedStatus_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.SelectedStatus))
                fired = true;
        };

        vm.SelectedStatus = ReviewsReviewStatus.FalsePositive;
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // 5. Exception visibility
    // ------------------------------------------------------------------

    [Fact]
    public void IsExceptionStatus_true_only_when_ApprovedException()
    {
        var vm = CreateViewModel();

        foreach (ReviewsReviewStatus status in Enum.GetValues<ReviewsReviewStatus>())
        {
            vm.SelectedStatus = status;
            if (status == ReviewsReviewStatus.ApprovedException)
                Assert.True(vm.IsExceptionStatus, $"Expected IsExceptionStatus=true for {status}");
            else
                Assert.False(vm.IsExceptionStatus, $"Expected IsExceptionStatus=false for {status}");
        }
    }

    // ------------------------------------------------------------------
    // 6. Reason validation
    // ------------------------------------------------------------------

    [Fact]
    public void Submit_cannot_execute_with_empty_reason_when_selection_exists()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));

        // HasSelection is true but Reason is empty
        Assert.True(vm.HasSelection);
        Assert.Equal("", vm.Reason);
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Submit_cannot_execute_with_whitespace_only_reason()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "   ";

        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Submit_can_execute_with_non_empty_reason_and_selection()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "确认为有效风险";

        Assert.True(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Clearing_reason_disables_submit()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "初版理由";
        Assert.True(vm.SubmitReviewCommand.CanExecute(null));

        vm.Reason = "";
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    // ------------------------------------------------------------------
    // 7. Submit button gating (HasSelection + !IsSubmitting + Reason)
    // ------------------------------------------------------------------

    [Fact]
    public void Submit_cannot_execute_when_no_selection_even_with_reason()
    {
        var vm = CreateViewModel();
        vm.Reason = "有理由但没有选中项";

        Assert.False(vm.HasSelection);
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Submit_cannot_execute_when_IsSubmitting_is_true()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "有效理由";
        Assert.True(vm.SubmitReviewCommand.CanExecute(null));

        vm.IsSubmitting = true;
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void Submit_can_execute_again_after_IsSubmitting_returns_to_false()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "有效理由";

        vm.IsSubmitting = true;
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));

        vm.IsSubmitting = false;
        Assert.True(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void All_three_conditions_must_be_met_for_submit()
    {
        var vm = CreateViewModel();

        // None met
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));

        // Only HasSelection
        vm.SetSelection(new ScanId(Guid.NewGuid()), null,
            new FindingOccurrenceId(Guid.NewGuid()));
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));

        // HasSelection + IsSubmitting=true (but no reason)
        vm.IsSubmitting = true;
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));

        // HasSelection + reason but IsSubmitting=true
        vm.Reason = "测试理由";
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));

        // All met
        vm.IsSubmitting = false;
        Assert.True(vm.SubmitReviewCommand.CanExecute(null));
    }

    // ------------------------------------------------------------------
    // 8. IsSubmitting gating
    // ------------------------------------------------------------------

    [Fact]
    public void IsSubmitting_set_to_true_disables_submit()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        vm.Reason = "有效理由";
        Assert.True(vm.SubmitReviewCommand.CanExecute(null));

        vm.IsSubmitting = true;
        Assert.False(vm.SubmitReviewCommand.CanExecute(null));
    }

    [Fact]
    public void IsSubmitting_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.IsSubmitting))
                fired = true;
        };

        vm.IsSubmitting = true;
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // PropertyChanged notifications
    // ------------------------------------------------------------------

    [Fact]
    public void HasSelection_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.HasSelection))
                fired = true;
        };

        vm.SetSelection(new ScanId(Guid.NewGuid()), null,
            new FindingOccurrenceId(Guid.NewGuid()));
        Assert.True(fired);
    }

    [Fact]
    public void Reason_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.Reason))
                fired = true;
        };

        vm.Reason = "测试理由";
        Assert.True(fired);
    }

    [Fact]
    public void Timeline_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ReviewViewModel.Timeline))
                fired = true;
        };

        vm.Timeline = new ObservableCollection<ReviewTimelineEntry>();
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // CanExecuteChanged propagation
    // ------------------------------------------------------------------

    [Fact]
    public void Reason_change_triggers_CanExecuteChanged()
    {
        var vm = CreateViewModel();
        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));

        bool canExecuteChangedFired = false;
        vm.SubmitReviewCommand.CanExecuteChanged += (_, _) =>
            canExecuteChangedFired = true;

        vm.Reason = "触发刷新";
        Assert.True(canExecuteChangedFired);
    }

    [Fact]
    public void HasSelection_change_triggers_CanExecuteChanged()
    {
        var vm = CreateViewModel();
        bool canExecuteChangedFired = false;
        vm.SubmitReviewCommand.CanExecuteChanged += (_, _) =>
            canExecuteChangedFired = true;

        vm.SetSelection(
            new ScanId(Guid.NewGuid()),
            null,
            new FindingOccurrenceId(Guid.NewGuid()));
        Assert.True(canExecuteChangedFired);
    }

    [Fact]
    public void IsSubmitting_change_triggers_CanExecuteChanged()
    {
        var vm = CreateViewModel();
        bool canExecuteChangedFired = false;
        vm.SubmitReviewCommand.CanExecuteChanged += (_, _) =>
            canExecuteChangedFired = true;

        vm.IsSubmitting = true;
        Assert.True(canExecuteChangedFired);
    }

    // ------------------------------------------------------------------
    // Exception binding fields
    // ------------------------------------------------------------------

    [Fact]
    public void Exception_fields_default_to_empty_strings()
    {
        var vm = CreateViewModel();

        Assert.Equal("", vm.ExceptionAssetId);
        Assert.Equal("", vm.ExceptionAssetVersion);
        Assert.Equal("", vm.ExceptionFilePath);
        Assert.Equal("", vm.ExceptionLocator);
        Assert.Equal("", vm.ExceptionFindingValue);
        Assert.Equal("", vm.ExceptionRulePackHash);
        Assert.Equal("", vm.ExceptionRuleId);
    }

    [Fact]
    public void ExceptionExpiry_is_about_90_days_from_now()
    {
        var vm = CreateViewModel();
        var now = DateTimeOffset.UtcNow;
        var ninetyDays = now.AddDays(90);

        // Allow ±2 seconds tolerance for test execution timing
        var diff = (vm.ExceptionExpiry - ninetyDays).Duration();
        Assert.True(diff < TimeSpan.FromSeconds(2),
            $"Expected expiry close to {ninetyDays:O}, got {vm.ExceptionExpiry:O}");
    }

    // ------------------------------------------------------------------
    // Command is ICommand
    // ------------------------------------------------------------------

    [Fact]
    public void SubmitReviewCommand_is_ICommand()
    {
        var vm = CreateViewModel();
        Assert.IsAssignableFrom<ICommand>(vm.SubmitReviewCommand);
    }
}
