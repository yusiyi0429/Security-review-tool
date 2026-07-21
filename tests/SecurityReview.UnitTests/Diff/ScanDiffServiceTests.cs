using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diff;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Rules;
using SecurityReview.Domain.Scans;
using ReviewDifferenceStatus = SecurityReview.Domain.Reviews.DifferenceStatus;

namespace SecurityReview.UnitTests.Diff;

public sealed class ScanDiffServiceTests
{
    // ---------------------------------------------------------------
    // Stubs
    // ---------------------------------------------------------------

    private sealed class StubFindingRepository : IFindingRepository
    {
        private readonly Dictionary<ScanId, ScanFindings> _scans = new();

        public void AddScan(ScanId scanId, IReadOnlyList<FindingGroup> groups,
            IReadOnlyList<FindingOccurrence> occurrences)
        {
            _scans[scanId] = new ScanFindings(groups, occurrences);
        }

        public Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(
            ScanId scanId, CancellationToken ct)
        {
            if (_scans.TryGetValue(scanId, out var sf))
                return Task.FromResult(sf.Groups);
            return Task.FromResult<IReadOnlyList<FindingGroup>>(Array.Empty<FindingGroup>());
        }

        public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(
            FindingGroupId groupId, CancellationToken ct)
        {
            foreach (var sf in _scans.Values)
            {
                // Find the group and return its occurrences.
                var group = sf.Groups.FirstOrDefault(g => g.Id == groupId);
                if (group is not null)
                {
                    var occs = sf.Occurrences
                        .Where(o => o.GroupId == groupId)
                        .ToList();
                    return Task.FromResult<IReadOnlyList<FindingOccurrence>>(occs);
                }
            }
            return Task.FromResult<IReadOnlyList<FindingOccurrence>>(Array.Empty<FindingOccurrence>());
        }

        Task IFindingRepository.InsertGroupAsync(ScanId scanId, FindingGroup group, CancellationToken ct)
            => throw new NotSupportedException();
        Task IFindingRepository.InsertOccurrenceAsync(FileId fileId, FindingOccurrence occurrence, CancellationToken ct)
            => throw new NotSupportedException();
        Task IFindingRepository.InsertOccurrenceBatchAsync(FileId fileId, IReadOnlyList<FindingOccurrence> occurrences, CancellationToken ct)
            => throw new NotSupportedException();
        Task<FindingGroup?> IFindingRepository.GetGroupByIdAsync(FindingGroupId id, CancellationToken ct)
            => throw new NotSupportedException();

        private sealed record ScanFindings(
            IReadOnlyList<FindingGroup> Groups,
            IReadOnlyList<FindingOccurrence> Occurrences);
    }

    private sealed class StubCoverageRepository : ICoverageRepository
    {
        private readonly List<CoverageGap> _gaps = new();

        public void AddGap(CoverageGap gap) => _gaps.Add(gap);

        public Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(
            ScanId scanId, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CoverageGap>>(_gaps.ToList());

        Task ICoverageRepository.InsertAsync(CoverageGap gap, CancellationToken ct)
            => throw new NotSupportedException();
        Task ICoverageRepository.InsertBatchAsync(IReadOnlyList<CoverageGap> gaps, CancellationToken ct)
            => throw new NotSupportedException();
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static FindingGroup CreateGroup(
        FindingGroupId id, ValueFingerprint fingerprint,
        params FindingOccurrence[] occurrences)
    {
        return new FindingGroup(id, FindingKind.SensitiveContent, Severity.High,
            fingerprint, occurrences.ToList());
    }

    private static FindingOccurrence CreateOccurrence(
        FindingOccurrenceId id, FindingGroupId groupId,
        string rawValue, string virtualPath,
        SourceLocator locator, string fileSha256,
        RuleId ruleId, DetectorId detectorId)
    {
        var provenance = new FindingProvenance(
            detectorId, ruleId, DetectionConfidence.High, false);
        return new FindingOccurrence(
            id, groupId, rawValue, string.Empty, locator, virtualPath,
            fileSha256, [provenance]);
    }

    private static SourceLocator.TextLocator TextLoc(long line, long col, long start, long len)
        => new(line, col, start, len);

    private static ScanId NewScanId() => new(Guid.NewGuid());
    private static FindingGroupId NewGroupId() => new(Guid.NewGuid());
    private static FindingOccurrenceId NewOccId() => new(Guid.NewGuid());

    // ---------------------------------------------------------------
    // No previous scan — all findings are New
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_NoPreviousScan_AllFindingsAreNew()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var groupId = NewGroupId();
        var occId = NewOccId();

        var groups = new[] { CreateGroup(groupId,
            new ValueFingerprint("abc123"), CreateOccurrence(
                occId, groupId, "secret", "/files/doc.xlsx",
                TextLoc(3, 2, 100, 6), "file-sha256-001",
                new RuleId("RULE-001"), new DetectorId("DET-001"))) };

        var occurrences = groups.SelectMany(g => g.Occurrences).ToList();

        var diffs = await service.ComputeDiffAsync(
            currentScan, null, groups, occurrences.AsReadOnly(),
            false, null);

        Assert.Single(diffs);
        Assert.Equal(ReviewDifferenceStatus.New, diffs[0].Status);
    }

    // ---------------------------------------------------------------
    // Persistent — same binding in both scans
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_SameFindingInBothScans_ReturnsPersistent()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var previousScan = NewScanId();

        var groupId = NewGroupId();
        var occId1 = NewOccId(); // current occurrence
        var occId2 = NewOccId(); // previous occurrence

        var fingerprint = new ValueFingerprint("abc123");
        var virtualPath = "/files/doc.xlsx";
        var fileSha256 = "file-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var locator = TextLoc(3, 2, 100, 6);
        var ruleId = new RuleId("RULE-001");
        var detectorId = new DetectorId("DET-001");

        // Current scan findings
        var currentOcc = CreateOccurrence(occId1, groupId, "secret", virtualPath,
            locator, fileSha256, ruleId, detectorId);
        var currentGroup = CreateGroup(groupId, fingerprint, currentOcc);
        findRepo.AddScan(currentScan, [currentGroup], [currentOcc]);

        // Previous scan findings (same binding)
        var prevOcc = CreateOccurrence(occId2, groupId, "secret", virtualPath,
            locator, fileSha256, ruleId, detectorId);
        var prevGroup = CreateGroup(groupId, fingerprint, prevOcc);
        findRepo.AddScan(previousScan, [prevGroup], [prevOcc]);

        var diffs = await service.ComputeDiffAsync(
            currentScan, previousScan,
            [currentGroup], [currentOcc],
            false, null);

        var currentDiff = diffs.First(d => d.OccurrenceId == occId1);
        Assert.Equal(ReviewDifferenceStatus.Persistent, currentDiff.Status);
    }

    // ---------------------------------------------------------------
    // Resolved — location covered, finding gone
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_FindingGoneAndLocationCovered_ReturnsResolved()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var previousScan = NewScanId();

        var groupId = NewGroupId();
        var prevOccId = NewOccId();
        var fingerprint = new ValueFingerprint("abc123");
        var virtualPath = "/files/doc.xlsx";
        var fileSha256 = "file-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Previous scan has a finding
        var prevOcc = CreateOccurrence(prevOccId, groupId, "secret", virtualPath,
            TextLoc(3, 2, 100, 6), fileSha256,
            new RuleId("RULE-001"), new DetectorId("DET-001"));
        var prevGroup = CreateGroup(groupId, fingerprint, prevOcc);
        findRepo.AddScan(previousScan, [prevGroup], [prevOcc]);

        // Current scan has no findings, and the location is covered (no gaps for that path).
        // No gaps means covered.

        var diffs = await service.ComputeDiffAsync(
            currentScan, previousScan,
            Array.Empty<FindingGroup>(), Array.Empty<FindingOccurrence>(),
            false, null);

        var resolvedDiff = diffs.First(d => d.OccurrenceId == prevOccId);
        Assert.Equal(ReviewDifferenceStatus.Resolved, resolvedDiff.Status);
    }

    // ---------------------------------------------------------------
    // UnreviewableThisRun — finding gone, location not covered
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_FindingGoneAndLocationNotCovered_ReturnsUnreviewableThisRun()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var previousScan = NewScanId();

        var groupId = NewGroupId();
        var prevOccId = NewOccId();
        var fingerprint = new ValueFingerprint("abc123");
        var virtualPath = "/files/doc.xlsx";
        var fileSha256 = "file-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Previous scan has a finding
        var prevOcc = CreateOccurrence(prevOccId, groupId, "secret", virtualPath,
            TextLoc(3, 2, 100, 6), fileSha256,
            new RuleId("RULE-001"), new DetectorId("DET-001"));
        var prevGroup = CreateGroup(groupId, fingerprint, prevOcc);
        findRepo.AddScan(previousScan, [prevGroup], [prevOcc]);

        // Location NOT covered: add a coverage gap for this path.
        covRepo.AddGap(new CoverageGap(
            GapId: Guid.NewGuid(),
            ScanId: currentScan,
            FileId: null,
            VirtualPath: virtualPath,
            FormatId: "xlsx",
            Stage: "parse",
            Reason: GapReason.AccessDenied,
            DetailCode: "E_ACCESS_DENIED",
            PlannedBytes: null,
            ProcessedBytes: null,
            CreatedAtUtc: DateTimeOffset.UtcNow));

        var diffs = await service.ComputeDiffAsync(
            currentScan, previousScan,
            Array.Empty<FindingGroup>(), Array.Empty<FindingOccurrence>(),
            false, null);

        var unreviewableDiff = diffs.First(d => d.OccurrenceId == prevOccId);
        Assert.Equal(ReviewDifferenceStatus.UnreviewableThisRun, unreviewableDiff.Status);
    }

    // ---------------------------------------------------------------
    // ReappearedAfterRuleChange — new rule, same location/value
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_SameLocationValueButNewlyEnabledRule_ReturnsReappearedAfterRuleChange()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var previousScan = NewScanId();

        var groupId = NewGroupId();
        var currentOccId = NewOccId();
        var prevOccId = NewOccId();

        var fingerprint = new ValueFingerprint("abc123");
        var virtualPath = "/files/doc.xlsx";
        var fileSha256 = "file-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var locator = TextLoc(3, 2, 100, 6);

        // Current has finding with a newly-enabled rule
        var newRuleId = new RuleId("RULE-NEW-001");
        var currentOcc = CreateOccurrence(currentOccId, groupId, "secret", virtualPath,
            locator, fileSha256, newRuleId, new DetectorId("DET-001"));
        var currentGroup = CreateGroup(groupId, fingerprint, currentOcc);
        findRepo.AddScan(currentScan, [currentGroup], [currentOcc]);

        // Previous has finding with the old rule at same location/value
        var oldRuleId = new RuleId("RULE-OLD-001");
        var prevOcc = CreateOccurrence(prevOccId, groupId, "secret", virtualPath,
            locator, fileSha256, oldRuleId, new DetectorId("DET-001"));
        var prevGroup = CreateGroup(groupId, fingerprint, prevOcc);
        findRepo.AddScan(previousScan, [prevGroup], [prevOcc]);

        var newlyEnabled = new HashSet<string> { "RULE-NEW-001" };

        var diffs = await service.ComputeDiffAsync(
            currentScan, previousScan,
            [currentGroup], [currentOcc],
            rulePackChanged: true, newlyEnabledRuleIds: newlyEnabled);

        var currentDiff = diffs.First(d => d.OccurrenceId == currentOccId);
        Assert.Equal(ReviewDifferenceStatus.ReappearedAfterRuleChange, currentDiff.Status);
    }

    // ---------------------------------------------------------------
    // Content changed — New
    // ---------------------------------------------------------------

    [Fact]
    public async Task ComputeDiff_DifferentValueSameLocation_ReturnsNew()
    {
        var findRepo = new StubFindingRepository();
        var covRepo = new StubCoverageRepository();
        var service = new ScanDiffService(findRepo, covRepo);

        var currentScan = NewScanId();
        var previousScan = NewScanId();

        var groupId = NewGroupId();
        var currentOccId = NewOccId();
        var prevOccId = NewOccId();

        var virtualPath = "/files/doc.xlsx";
        var fileSha256 = "file-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var locator = TextLoc(3, 2, 100, 8);

        // Current has a different value at the same location
        var currentFingerprint = new ValueFingerprint("def456");
        var currentOcc = CreateOccurrence(currentOccId, groupId, "newsecret", virtualPath,
            locator, fileSha256, new RuleId("RULE-001"), new DetectorId("DET-001"));
        var currentGroup = CreateGroup(groupId, currentFingerprint, currentOcc);
        findRepo.AddScan(currentScan, [currentGroup], [currentOcc]);

        // Previous has old value
        var prevFingerprint = new ValueFingerprint("abc123");
        var prevOcc = CreateOccurrence(prevOccId, groupId, "oldsecret", virtualPath,
            locator, fileSha256, new RuleId("RULE-001"), new DetectorId("DET-001"));
        var prevGroup = CreateGroup(groupId, prevFingerprint, prevOcc);
        findRepo.AddScan(previousScan, [prevGroup], [prevOcc]);

        var diffs = await service.ComputeDiffAsync(
            currentScan, previousScan,
            [currentGroup], [currentOcc],
            false, null);

        var currentDiff = diffs.First(d => d.OccurrenceId == currentOccId);
        Assert.Equal(ReviewDifferenceStatus.New, currentDiff.Status);

        var prevDiff = diffs.First(d => d.OccurrenceId == prevOccId);
        Assert.Equal(ReviewDifferenceStatus.Resolved, prevDiff.Status);
    }
}
