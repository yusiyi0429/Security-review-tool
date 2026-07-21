using System.Collections.ObjectModel;
using System.Globalization;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.History;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Rules;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Desktop;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using ReviewsReviewStatus = SecurityReview.Domain.Reviews.ReviewStatus;

namespace SecurityReview.IntegrationTests.Desktop;

/// <summary>
/// Integration tests for the desktop workflow: navigation, safe preview,
/// review view model, history view model, composition root lifecycle,
/// and navigation entry invariants.
/// </summary>
public sealed class DesktopWorkflowTests : IAsyncDisposable
{
    private readonly string _tempDir;

    public DesktopWorkflowTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_tempDir);
    }

    public ValueTask DisposeAsync()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }
        return ValueTask.CompletedTask;
    }

    // ==================================================================
    // 1. NavigationService — NavigateTo fires Navigated event with correct entry
    // ==================================================================

    [Fact]
    public void NavigateTo_fires_Navigated_event_with_correct_entry()
    {
        var nav = new NavigationService();
        NavigationEntry? received = null;
        nav.Navigated += e => received = e;

        nav.NavigateTo(NavigationEntry.任务历史);

        Assert.Equal(NavigationEntry.任务历史, received);
        Assert.Equal(NavigationEntry.任务历史, nav.CurrentEntry);
    }

    [Fact]
    public void NavigateTo_same_entry_does_not_fire_duplicate_event()
    {
        var nav = new NavigationService();
        int fireCount = 0;
        nav.Navigated += _ => fireCount++;

        nav.NavigateTo(NavigationEntry.新建扫描);
        nav.NavigateTo(NavigationEntry.新建扫描);

        Assert.Equal(1, fireCount);
    }

    // ==================================================================
    // 2. SafePreviewService with real text — creates bounded fragments, highlights correct lines
    // ==================================================================

    [Fact]
    public void PreviewText_creates_bounded_fragment_around_locator()
    {
        var lines = Enumerable.Range(1, 50).Select(i => $"line {i:D2}: some content here").ToArray();
        string fullText = string.Join('\n', lines);
        var locator = new SourceLocator.TextLocator(25, 0, 0, 0);

        var fragment = SafePreviewService.PreviewText(fullText, locator);

        Assert.NotNull(fragment);
        Assert.NotEmpty(fragment.Lines);
        Assert.True(fragment.HighlightLineIndex >= 0);
        Assert.True(fragment.TruncatedBefore >= 0);
        Assert.True(fragment.TruncatedAfter >= 0);
        Assert.NotEmpty(fragment.LocatorDisplay);
    }

    [Fact]
    public void PreviewText_highlights_the_correct_line()
    {
        var lines = Enumerable.Range(1, 30).Select(i => $"line {i:D2}: content").ToArray();
        string fullText = string.Join('\n', lines);
        var locator = new SourceLocator.TextLocator(15, 0, 0, 0);

        var fragment = SafePreviewService.PreviewText(fullText, locator);

        Assert.NotNull(fragment);
        int highlightLineIndex = fragment.HighlightLineIndex;
        Assert.True(highlightLineIndex >= 0 && highlightLineIndex < fragment.Lines.Count);
        Assert.Contains("line 15:", fragment.Lines[highlightLineIndex].Text);
    }

    [Fact]
    public void PreviewText_handles_text_shorter_than_max_lines()
    {
        var lines = new[] { "short", "text", "file" };
        string fullText = string.Join('\n', lines);
        var locator = new SourceLocator.TextLocator(0, 0, 0, 0);

        var fragment = SafePreviewService.PreviewText(fullText, locator);

        Assert.NotNull(fragment);
        Assert.Equal(3, fragment.Lines.Count);
        Assert.Equal(0, fragment.TruncatedBefore);
        Assert.Equal(0, fragment.TruncatedAfter);
    }

    // ==================================================================
    // 3. ReviewViewModel with stub service — SetSelection/LoadTimeline/status changes
    // ==================================================================

    [Fact]
    public void SetSelection_sets_HasSelection_and_updates_CurrentUser()
    {
        var stub = new FakeReviewService();
        var sink = new TestErrorSink();
        var vm = new ReviewViewModel(stub, sink);
        var scanId = new ScanId(Guid.NewGuid());
        var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());

        vm.SetSelection(scanId, groupId: null, occurrenceId);

        Assert.True(vm.HasSelection);
        Assert.NotEmpty(vm.CurrentUser);
        Assert.NotEmpty(vm.CurrentTime);
    }

    [Fact]
    public void SetSelection_with_null_occurrence_and_group_sets_HasSelection_false()
    {
        var stub = new FakeReviewService();
        var sink = new TestErrorSink();
        var vm = new ReviewViewModel(stub, sink);
        var scanId = new ScanId(Guid.NewGuid());

        vm.SetSelection(scanId, groupId: null, occurrenceId: null);

        Assert.False(vm.HasSelection);
    }

    [Fact]
    public void LoadTimeline_populates_timeline_in_chronological_order()
    {
        var stub = new FakeReviewService();
        var sink = new TestErrorSink();
        var vm = new ReviewViewModel(stub, sink);
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;

        var decisions = new List<ReviewDecision>
        {
            new ReviewDecision(
                new DecisionId(Guid.NewGuid()), scanId, null,
                new FindingOccurrenceId(Guid.NewGuid()),
                ReviewsReviewStatus.Pending, "initial", null,
                "user-hmac", now.AddMinutes(-5)),
            new ReviewDecision(
                new DecisionId(Guid.NewGuid()), scanId, null,
                new FindingOccurrenceId(Guid.NewGuid()),
                ReviewsReviewStatus.ConfirmedRisk, "manual_review", "enc-reason",
                "user-hmac", now),
            new ReviewDecision(
                new DecisionId(Guid.NewGuid()), scanId, null,
                new FindingOccurrenceId(Guid.NewGuid()),
                ReviewsReviewStatus.FalsePositive, "fp_review", "enc-reason",
                "user-hmac", now.AddMinutes(-10)),
        };

        vm.LoadTimeline(decisions);

        Assert.Equal(3, vm.Timeline.Count);
        // Should be ordered by DecidedAtUtc ascending
        Assert.Equal(ReviewsReviewStatus.FalsePositive, vm.Timeline[0].Status);
        Assert.Equal(ReviewsReviewStatus.Pending, vm.Timeline[1].Status);
        Assert.Equal(ReviewsReviewStatus.ConfirmedRisk, vm.Timeline[2].Status);
    }

    [Fact]
    public void SelectedStatus_tracks_exception_status_flag()
    {
        var stub = new FakeReviewService();
        var sink = new TestErrorSink();
        var vm = new ReviewViewModel(stub, sink);

        Assert.False(vm.IsExceptionStatus);

        vm.SelectedStatus = ReviewsReviewStatus.ApprovedException;

        Assert.True(vm.IsExceptionStatus);
        Assert.Equal(ReviewsReviewStatus.ApprovedException, vm.SelectedStatus);
    }

    // ==================================================================
    // 4. HistoryViewModel with stub query — RefreshAsync populates Scans
    // ==================================================================

    [Fact]
    public async Task RefreshAsync_populates_Scans_collection()
    {
        using var root = BuildRoot();
        var sink = root.GetService<IUiErrorSink>();
        var scanRepo = new FakeScanRepository();
        var queryService = new ScanQueryService(
            scanRepo, root.GetService<IFindingRepository>(),
            root.GetService<ICoverageRepository>(),
            root.GetService<IFileRepository>(),
            root.GetService<IReviewService>());
        var rescanHandler = root.GetService<RescanHandler>();

        var vm = new HistoryViewModel(
            () => queryService,
            () => rescanHandler,
            () => throw new InvalidOperationException("RetentionService not used by RefreshAsync"),
            sink);

        await vm.RefreshAsync();

        Assert.NotNull(vm.Scans);
    }

    [Fact]
    public async Task RefreshAsync_with_scan_data_populates_items()
    {
        var scanRepo = new FakeScanRepository();
        var scanRun = new ScanRun(
            new ScanId(Guid.NewGuid()),
            ScanStatus.Completed,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow,
            "rulefingerprint12345678",
            "clientfingerprint12345678",
            "pipelinepipeline12345678",
            10,
            1);
        scanRepo.AddScan(scanRun);

        using var root = BuildRoot();
        var sink = root.GetService<IUiErrorSink>();
        var queryService = new ScanQueryService(
            scanRepo, root.GetService<IFindingRepository>(),
            root.GetService<ICoverageRepository>(),
            root.GetService<IFileRepository>(),
            root.GetService<IReviewService>());
        var rescanHandler = root.GetService<RescanHandler>();

        var vm = new HistoryViewModel(
            () => queryService,
            () => rescanHandler,
            () => throw new InvalidOperationException("RetentionService not used by RefreshAsync"),
            sink);

        await vm.RefreshAsync();

        Assert.NotEmpty(vm.Scans);
        Assert.Equal(scanRun.ScanId, vm.Scans[0].ScanId);
        Assert.Equal(ScanStatus.Completed, vm.Scans[0].Status);
        Assert.Equal("rulefin", vm.Scans[0].RulePackPrefix);
        Assert.Equal("clientf", vm.Scans[0].ClientFingerprintPrefix);
        Assert.Equal("pipelin", vm.Scans[0].InputHashPrefix);
    }

    // ==================================================================
    // 5. CompositionRoot builds — ForTest composition root can be constructed and disposed
    // ==================================================================

    [Fact]
    public void ForTest_composition_root_can_be_constructed_and_disposed()
    {
        var root = new CompositionRoot(CompositionRoot.Args.ForTest(_tempDir));

        // Verify core services are resolvable
        Assert.NotNull(root.GetService<ISqliteConnectionFactory>());
        Assert.NotNull(root.GetService<IPayloadProtector>());
        Assert.NotNull(root.GetService<IRulePackStore>());
        Assert.NotNull(root.GetService<ISandboxSelfTest>());
        Assert.NotNull(root.GetService<NavigationService>());
        Assert.NotNull(root.GetService<IUiErrorSink>());

        root.Dispose();
    }

    [Fact]
    public void ForTest_composition_root_resolves_ReviewService()
    {
        using var root = BuildRoot();
        var svc = root.GetService<IReviewService>();
        Assert.NotNull(svc);
    }

    [Fact]
    public void ForTest_composition_root_resolves_ScanQueryService()
    {
        using var root = BuildRoot();
        var svc = root.GetService<ScanQueryService>();
        Assert.NotNull(svc);
    }

    // ==================================================================
    // 6. Navigation entries — all 5 NavigationEntry values are distinct
    // ==================================================================

    [Fact]
    public void All_five_NavigationEntry_values_are_distinct()
    {
        var values = Enum.GetValues<NavigationEntry>();

        Assert.Equal(5, values.Length);
        Assert.Equal(5, values.Distinct().Count());
    }

    [Fact]
    public void NavigationEntry_has_expected_values()
    {
        var values = Enum.GetValues<NavigationEntry>();

        Assert.Contains(NavigationEntry.新建扫描, values);
        Assert.Contains(NavigationEntry.任务历史, values);
        Assert.Contains(NavigationEntry.规则管理, values);
        Assert.Contains(NavigationEntry.LLM设置, values);
        Assert.Contains(NavigationEntry.诊断与帮助, values);
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    private CompositionRoot BuildRoot()
    {
        return new CompositionRoot(CompositionRoot.Args.ForTest(_tempDir));
    }

    /// <summary>
    /// Stub IUiErrorSink for test assertions.
    /// </summary>
    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();
        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }

    /// <summary>
    /// Fake IReviewService that records calls for verification.
    /// </summary>
    private sealed class FakeReviewService : IReviewService
    {
        public List<RecordReviewCommand> RecordedCommands { get; } = new();
        public List<GrantExceptionCommand> GrantedCommands { get; } = new();

        public Task<ReviewDecision> RecordReviewAsync(
            RecordReviewCommand command, CancellationToken ct = default)
        {
            RecordedCommands.Add(command);
            var decision = new ReviewDecision(
                new DecisionId(Guid.NewGuid()),
                command.ScanId,
                command.GroupId,
                command.OccurrenceId,
                command.Status,
                command.ReasonCode,
                "encrypted-reason",
                "user-sid-hmac",
                DateTimeOffset.UtcNow);
            return Task.FromResult(decision);
        }

        public Task<ExceptionGrant> GrantExceptionAsync(
            GrantExceptionCommand command, CancellationToken ct = default)
        {
            GrantedCommands.Add(command);
            var binding = new ExceptionBinding(
                command.AssetId, command.AssetVersion,
                command.FilePath, command.CanonicalLocator,
                command.FindingValue, command.RulePackHash, command.RuleId);
            var grant = new ExceptionGrant(
                new ExceptionGrantId(Guid.NewGuid()),
                binding,
                command.RulePackHash,
                command.ValidUntilUtc,
                DateTimeOffset.UtcNow,
                "user-sid-hmac",
                "encrypted-reason");
            return Task.FromResult(grant);
        }

        public Task<EffectiveReviewResult> GetEffectiveStatusAsync(
            FindingOccurrenceId occurrenceId,
            string assetBindingHmac,
            string occurrenceBindingHmac,
            CancellationToken ct = default)
        {
            return Task.FromResult(new EffectiveReviewResult(
                ReviewsReviewStatus.Pending, "pending", null));
        }
    }

    /// <summary>
    /// Fake IScanRepository with in-memory scan storage.
    /// </summary>
    private sealed class FakeScanRepository : IScanRepository
    {
        private readonly List<ScanRun> _scans = new();

        public void AddScan(ScanRun scan) => _scans.Add(scan);

        public Task InsertAsync(ScanRun scan, CancellationToken ct = default)
        {
            _scans.Add(scan);
            return Task.CompletedTask;
        }

        public Task<ScanRun?> GetByIdAsync(ScanId scanId, CancellationToken ct = default)
        {
            return Task.FromResult(_scans.FirstOrDefault(s => s.ScanId == scanId));
        }

        public Task<IReadOnlyList<ScanRun>> ListAsync(CancellationToken ct = default)
        {
            return Task.FromResult<IReadOnlyList<ScanRun>>(_scans.AsReadOnly());
        }

        public Task<bool> TryTransitionAsync(
            ScanId scanId, ScanStatus expectedStatus, long expectedVersion,
            ScanStatus nextStatus, CancellationToken ct = default)
        {
            var scan = _scans.FirstOrDefault(s => s.ScanId == scanId);
            if (scan is null || scan.Status != expectedStatus || scan.Version != expectedVersion)
                return Task.FromResult(false);

            _scans.Remove(scan);
            _scans.Add(scan.TransitionTo(nextStatus, DateTimeOffset.UtcNow));
            return Task.FromResult(true);
        }

        public Task UpdateAsync(ScanRun scan, CancellationToken ct = default)
        {
            _scans.RemoveAll(s => s.ScanId == scan.ScanId);
            _scans.Add(scan);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ScanRun>> ListByStatusAsync(
            IReadOnlyList<ScanStatus> statuses, CancellationToken ct = default)
        {
            var hashSet = new HashSet<ScanStatus>(statuses);
            return Task.FromResult<IReadOnlyList<ScanRun>>(
                _scans.Where(s => hashSet.Contains(s.Status)).ToList().AsReadOnly());
        }

        public Task<ScanRun?> FindLatestPreviousAsync(
            string activeRulePackHash, string endpointFingerprint,
            CancellationToken ct = default)
        {
            return Task.FromResult<ScanRun?>(null);
        }
    }
}
