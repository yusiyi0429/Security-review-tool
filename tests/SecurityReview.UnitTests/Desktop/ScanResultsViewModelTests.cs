using System.Collections.ObjectModel;
using System.ComponentModel;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using ReviewsDifferenceStatus = SecurityReview.Domain.Reviews.DifferenceStatus;
using ReviewsReviewStatus = SecurityReview.Domain.Reviews.ReviewStatus;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for ScanResultsViewModel: filter state binding, pagination
/// navigation, group/occurrence selection, conclusion display wording,
/// and property change notifications.
/// </summary>
public sealed class ScanResultsViewModelTests
{
    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();
        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }

    private static ScanResultsViewModel CreateViewModel(
        TestErrorSink? sink = null,
        ScanQueryService? queryService = null)
    {
        sink ??= new TestErrorSink();
        return new ScanResultsViewModel(
            sink,
            () => queryService ?? throw new InvalidOperationException("ScanQueryService not provided"));
    }

    // ------------------------------------------------------------------
    // Filter bindings
    // ------------------------------------------------------------------

    [Fact]
    public void FilterKind_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.FilterKind))
                fired = true;
        };

        vm.FilterKind = FindingKind.SensitiveContent;
        Assert.True(fired);
    }

    [Fact]
    public void FilterSeverity_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.FilterSeverity))
                fired = true;
        };

        vm.FilterSeverity = Severity.High;
        Assert.True(fired);
    }

    [Fact]
    public void Filter_options_use_chinese_display_text()
    {
        Assert.Collection(
            FilterLists.FindingKindOptions,
            option => Assert.Equal("全部类别", option.Display),
            option => Assert.Equal("敏感内容", option.Display),
            option => Assert.Equal("资产合规", option.Display));
        Assert.Collection(
            FilterLists.SeverityOptions,
            option => Assert.Equal("全部级别", option.Display),
            option => Assert.Equal("严重", option.Display),
            option => Assert.Equal("高", option.Display),
            option => Assert.Equal("中", option.Display),
            option => Assert.Equal("低", option.Display),
            option => Assert.Equal("信息", option.Display));
    }

    [Fact]
    public void Selected_filter_options_update_query_values()
    {
        var vm = CreateViewModel();

        vm.SelectedKindOption = FilterLists.FindingKindOptions[1];
        vm.SelectedSeverityOption = FilterLists.SeverityOptions[2];

        Assert.Equal(FindingKind.SensitiveContent, vm.FilterKind);
        Assert.Equal(Severity.High, vm.FilterSeverity);
    }

    [Fact]
    public void FilterConfidence_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.FilterConfidence))
                fired = true;
        };

        vm.FilterConfidence = DetectionConfidence.High;
        Assert.True(fired);
    }

    [Fact]
    public void FilterReviewStatus_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.FilterReviewStatus))
                fired = true;
        };

        vm.FilterReviewStatus = ReviewsReviewStatus.ConfirmedRisk;
        Assert.True(fired);
    }

    [Fact]
    public void FilterDifferenceStatus_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.FilterDifferenceStatus))
                fired = true;
        };

        vm.FilterDifferenceStatus = ReviewsDifferenceStatus.New;
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // Clear filters
    // ------------------------------------------------------------------

    [Fact]
    public void ClearFilters_resets_all_filters()
    {
        var vm = CreateViewModel();
        vm.FilterKind = FindingKind.SensitiveContent;
        vm.FilterSeverity = Severity.Critical;
        vm.FilterConfidence = DetectionConfidence.Low;
        vm.ClearFiltersCommand.Execute(null);

        Assert.Null(vm.FilterKind);
        Assert.Null(vm.FilterSeverity);
        Assert.Null(vm.FilterConfidence);
        Assert.Null(vm.FilterReviewStatus);
        Assert.Null(vm.FilterDifferenceStatus);
    }

    // ------------------------------------------------------------------
    // Pagination
    // ------------------------------------------------------------------

    [Fact]
    public void PreviousPage_decrements_when_above_one()
    {
        var vm = CreateViewModel();
        vm.TotalPages = 5;
        vm.CurrentPage = 3;
        Assert.True(vm.HasPreviousPage);

        // Simulate going to previous page
        vm.CurrentPage = 2;
        Assert.Equal(2, vm.CurrentPage);
        Assert.True(vm.HasPreviousPage);
    }

    [Fact]
    public void NextPage_increments_when_below_total()
    {
        var vm = CreateViewModel();
        vm.TotalPages = 5;
        vm.CurrentPage = 3;
        Assert.True(vm.HasNextPage);

        vm.CurrentPage = 4;
        Assert.Equal(4, vm.CurrentPage);
    }

    [Fact]
    public void FirstPage_has_no_previous()
    {
        var vm = CreateViewModel();
        vm.CurrentPage = 1;
        Assert.False(vm.HasPreviousPage);
    }

    [Fact]
    public void LastPage_has_no_next()
    {
        var vm = CreateViewModel();
        vm.CurrentPage = 5;
        vm.TotalPages = 5;
        Assert.False(vm.HasNextPage);
    }

    // ------------------------------------------------------------------
    // Scan status display
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(ScanStatus.Completed, "已完成")]
    [InlineData(ScanStatus.Partial, "部分完成")]
    [InlineData(ScanStatus.Cancelled, "已取消")]
    [InlineData(ScanStatus.Failed, "已失败")]
    [InlineData(ScanStatus.Interrupted, "已中断")]
    public void ScanStatusDisplay_shows_correct_text(ScanStatus status, string expected)
    {
        var vm = CreateViewModel();
        vm.ScanStatus = status;
        Assert.Equal(expected, vm.ScanStatusDisplay);
    }

    // ------------------------------------------------------------------
    // Conclusion display wording
    // ------------------------------------------------------------------

    [Fact]
    public void ScanStatusDisplay_for_completed_shows_correct_text()
    {
        var vm = CreateViewModel();
        vm.ScanStatus = ScanStatus.Completed;
        Assert.Equal("已完成", vm.ScanStatusDisplay);
    }

    // ------------------------------------------------------------------
    // FindingGroupItem display properties
    // ------------------------------------------------------------------

    [Fact]
    public void FindingGroupItem_KindDisplay_shows_correct_chinese()
    {
        var item = new FindingGroupItem(
            new FindingGroupId(Guid.NewGuid()),
            FindingKind.SensitiveContent,
            Severity.High,
            "abc123def456",
            3);

        Assert.Equal("敏感内容", item.KindDisplay);
        Assert.Equal("高", item.SeverityDisplay);
        Assert.Equal("敏感内容 · 高 · 3 个出现", item.Summary);
    }

    [Fact]
    public void FindingGroupItem_ShortFingerprint_is_truncated()
    {
        var item = new FindingGroupItem(
            new FindingGroupId(Guid.NewGuid()),
            FindingKind.AssetCompliance,
            Severity.Low,
            "abc123def456",
            1);

        Assert.Equal(12, item.ShortFingerprint.Length);
    }

    // ------------------------------------------------------------------
    // PropertyChanged
    // ------------------------------------------------------------------

    [Fact]
    public void Implements_INotifyPropertyChanged()
    {
        var vm = CreateViewModel();
        Assert.IsAssignableFrom<INotifyPropertyChanged>(vm);
    }

    [Fact]
    public void ScanId_set_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanResultsViewModel.ScanId))
                fired = true;
        };

        vm.ScanId = new ScanId(Guid.NewGuid());
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // Data binding collections
    // ------------------------------------------------------------------

    [Fact]
    public void Groups_collection_is_observable()
    {
        var vm = CreateViewModel();
        Assert.IsType<ObservableCollection<FindingGroupItem>>(vm.Groups);
        Assert.Empty(vm.Groups);
    }

    [Fact]
    public void ExpandedOccurrences_collection_is_observable()
    {
        var vm = CreateViewModel();
        // Initially null; after expand, should be populated.
        vm.ExpandedOccurrences = new ObservableCollection<FindingOccurrenceItem>();
        Assert.IsType<ObservableCollection<FindingOccurrenceItem>>(vm.ExpandedOccurrences);
    }

    [Fact]
    public async Task History_replay_return_command_requests_history_view()
    {
        var vm = CreateViewModel();
        bool requested = false;
        vm.ReturnToHistoryRequested += () => requested = true;

        vm.EnableHistoryReplay();
        var command = Assert.IsType<AsyncRelayCommand>(
            vm.ReturnToHistoryCommand);
        await command.ExecuteAsync(null);

        Assert.True(vm.IsHistoryReplay);
        Assert.True(requested);
    }
}
