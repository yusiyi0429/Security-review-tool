using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class DetectorPipelineTests
{
    private static readonly DetectorId DetStructured = new("DET-STRUCTURED-FIELD");
    private static readonly DetectorId DetKnownFormat = new("DET-KNOWN-FORMAT");
    private static readonly DetectorId DetChecksum = new("DET-CHECKSUM");
    private static readonly DetectorId DetEntropy = new("DET-ENTROPY-CONTEXT");
    private static readonly DetectorId DetUnregistered = new("DET-UNREGISTERED");

    private static RuleDefinition MakeRule(string id, DetectorId detectorId, DetectorKind kind)
    {
        return new RuleDefinition
        {
            Id = new RuleId(id),
            CategoryId = CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.Medium,
            DetectorId = detectorId,
            DetectorConfigId = "default",
            AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
            Enabled = true
        };
    }

    private static DetectorDefinition MakeDetector(DetectorId id, DetectorKind kind)
    {
        return new DetectorDefinition
        {
            Id = id,
            Kind = kind,
            ConfigId = "default",
            Parameters = new Dictionary<string, string>(),
            MaxMatchesPerChunk = 5
        };
    }

    private static ContentChunk MakeTextChunk(string text)
    {
        return new ContentChunk(
            ProtocolVersion: 1,
            JobId: new JobId(Guid.NewGuid()),
            Sequence: 0,
            VirtualPath: "test.txt",
            FormatId: "text/plain",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: text,
            SourceStart: 0,
            SourceLength: text.Length,
            LocationMap: [],
            IsFinal: true);
    }

    private sealed class RecordingDetector : IDetector
    {
        private readonly List<DetectionCandidate> _candidates;

        public DetectorKind Kind { get; }
        public int CallCount { get; private set; }
        public bool ShouldThrow { get; set; }

        /// <summary>Shared execution log to verify call order across detectors.</summary>
        public static List<DetectorKind> ExecutionLog { get; } = [];

        public RecordingDetector(DetectorKind kind, List<DetectionCandidate>? candidates = null)
        {
            Kind = kind;
            _candidates = candidates ?? [];
        }

        public Task<IReadOnlyList<DetectionCandidate>> DetectAsync(
            ContentChunk chunk,
            RuleDefinition rule,
            DetectorDefinition detector,
            CancellationToken cancellationToken)
        {
            CallCount++;
            ExecutionLog.Add(Kind);

            if (ShouldThrow)
                throw new InvalidOperationException($"Detector {Kind} failure");

            return Task.FromResult<IReadOnlyList<DetectionCandidate>>(_candidates);
        }
    }

    // ---------- Stage order ----------

    [Fact]
    public async Task pipeline_executes_detectors_in_fixed_stage_order()
    {
        var recorders = new Dictionary<DetectorKind, RecordingDetector>
        {
            [DetectorKind.Checksum] = new(DetectorKind.Checksum),
            [DetectorKind.KnownFormat] = new(DetectorKind.KnownFormat),
            [DetectorKind.StructuredField] = new(DetectorKind.StructuredField),
        };

        var pipeline = new DetectorPipeline(recorders.Values);
        ContentChunk chunk = MakeTextChunk("hello");

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-KF", DetKnownFormat, DetectorKind.KnownFormat),
            MakeRule("RULE-CHK", DetChecksum, DetectorKind.Checksum),
            MakeRule("RULE-SF", DetStructured, DetectorKind.StructuredField),
        };

        var detectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [DetStructured] = MakeDetector(DetStructured, DetectorKind.StructuredField),
            [DetKnownFormat] = MakeDetector(DetKnownFormat, DetectorKind.KnownFormat),
            [DetChecksum] = MakeDetector(DetChecksum, DetectorKind.Checksum),
        };

        RecordingDetector.ExecutionLog.Clear();

        await pipeline.ExecuteAsync(chunk, rules, detectors, CancellationToken.None);

        // Stage order: StructuredField → KnownFormat → Checksum
        int sfIdx = RecordingDetector.ExecutionLog.IndexOf(DetectorKind.StructuredField);
        int kfIdx = RecordingDetector.ExecutionLog.IndexOf(DetectorKind.KnownFormat);
        int chkIdx = RecordingDetector.ExecutionLog.IndexOf(DetectorKind.Checksum);

        Assert.True(sfIdx >= 0);
        Assert.True(kfIdx >= 0);
        Assert.True(chkIdx >= 0);
        Assert.True(sfIdx < kfIdx);
        Assert.True(kfIdx < chkIdx);
    }

    // ---------- Exception handling ----------

    [Fact]
    public async Task detector_exception_creates_coverage_gap_not_safe()
    {
        var failingDetector = new RecordingDetector(DetectorKind.KnownFormat) { ShouldThrow = true };
        var pipeline = new DetectorPipeline([failingDetector]);

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-KF", DetKnownFormat, DetectorKind.KnownFormat),
        };

        var detectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [DetKnownFormat] = MakeDetector(DetKnownFormat, DetectorKind.KnownFormat),
        };

        ContentChunk chunk = MakeTextChunk("test");
        var result = await pipeline.ExecuteAsync(chunk, rules, detectors, CancellationToken.None);

        // Exception → coverage gap, not safe fallback
        Assert.Empty(result.Candidates);
        Assert.NotEmpty(result.CoverageGaps);
        Assert.Contains(result.CoverageGaps, g => g.DetectorKind == DetectorKind.KnownFormat);
    }

    [Fact]
    public async Task pipeline_continues_after_detector_exception()
    {
        var failingDetector = new RecordingDetector(DetectorKind.KnownFormat) { ShouldThrow = true };
        var workingDetector = new RecordingDetector(DetectorKind.Checksum);

        var pipeline = new DetectorPipeline([failingDetector, workingDetector]);

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-KF", DetKnownFormat, DetectorKind.KnownFormat),
            MakeRule("RULE-CHK", DetChecksum, DetectorKind.Checksum),
        };

        var detectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [DetKnownFormat] = MakeDetector(DetKnownFormat, DetectorKind.KnownFormat),
            [DetChecksum] = MakeDetector(DetChecksum, DetectorKind.Checksum),
        };

        ContentChunk chunk = MakeTextChunk("test");
        var result = await pipeline.ExecuteAsync(chunk, rules, detectors, CancellationToken.None);

        Assert.Single(result.CoverageGaps);
        Assert.Equal(1, workingDetector.CallCount);
    }

    // ---------- Cancellation ----------

    [Fact]
    public async Task cancellation_stops_after_current_bounded_operation()
    {
        var cts = new CancellationTokenSource();
        var longRunningDetector = new RecordingDetector(DetectorKind.KnownFormat);
        var pipeline = new DetectorPipeline([longRunningDetector]);

        // Cancel before execution
        await cts.CancelAsync();

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-KF", DetKnownFormat, DetectorKind.KnownFormat),
        };

        var detectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [DetKnownFormat] = MakeDetector(DetKnownFormat, DetectorKind.KnownFormat),
        };

        ContentChunk chunk = MakeTextChunk("test");

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => pipeline.ExecuteAsync(chunk, rules, detectors, cts.Token));
    }

    // ---------- Overlap dedup ----------

    [Fact]
    public async Task pipeline_deduplicates_by_dedup_key()
    {
        var candidate1 = DetectionCandidate.Create(
            "secret123", "", new SourceLocator.TextLocator(1, 1, 0, 9),
            new RuleId("RULE-DUP"), new DetectorId("DET-DUP"),
            Severity.High, DetectionConfidence.High, FindingKind.SensitiveContent);

        var candidate2 = DetectionCandidate.Create(
            "secret123", "", new SourceLocator.TextLocator(1, 1, 0, 9),
            new RuleId("RULE-DUP"), new DetectorId("DET-DUP"),
            Severity.High, DetectionConfidence.High, FindingKind.SensitiveContent);

        var detector = new RecordingDetector(DetectorKind.KnownFormat, [candidate1, candidate2]);
        var pipeline = new DetectorPipeline([detector]);

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-DUP", new DetectorId("DET-DUP"), DetectorKind.KnownFormat),
        };

        var ruleDetectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [new DetectorId("DET-DUP")] = MakeDetector(new DetectorId("DET-DUP"), DetectorKind.KnownFormat),
        };

        ContentChunk chunk = MakeTextChunk("secret123");
        var result = await pipeline.ExecuteAsync(chunk, rules, ruleDetectors, CancellationToken.None);

        Assert.Single(result.Candidates);
    }

    // ---------- Match limits ----------

    [Fact]
    public async Task pipeline_caps_matches_per_chunk()
    {
        var candidates = Enumerable.Range(0, 10).Select(i =>
            DetectionCandidate.Create(
                $"secret{i:D3}", "", new SourceLocator.TextLocator(1, i, 0, 9),
                new RuleId("RULE-CAP"), new DetectorId("DET-CAP"),
                Severity.Medium, DetectionConfidence.Low, FindingKind.SensitiveContent)
        ).ToList();

        var detector = new RecordingDetector(DetectorKind.KnownFormat, candidates);
        var pipeline = new DetectorPipeline([detector]);

        var detDef = MakeDetector(new DetectorId("DET-CAP"), DetectorKind.KnownFormat);
        detDef = detDef with { MaxMatchesPerChunk = 3 };

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-CAP", new DetectorId("DET-CAP"), DetectorKind.KnownFormat),
        };

        var ruleDetectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [new DetectorId("DET-CAP")] = detDef,
        };

        ContentChunk chunk = MakeTextChunk("test");
        var result = await pipeline.ExecuteAsync(chunk, rules, ruleDetectors, CancellationToken.None);

        Assert.Equal(3, result.Candidates.Count);
    }

    // ---------- Unregistered detector ----------

    [Fact]
    public async Task unregistered_detector_creates_coverage_gap()
    {
        var pipeline = new DetectorPipeline([]);

        var rules = new List<RuleDefinition>
        {
            MakeRule("RULE-UNREG", DetUnregistered, DetectorKind.Checksum),
        };

        var detectors = new Dictionary<DetectorId, DetectorDefinition>
        {
            [DetUnregistered] = MakeDetector(DetUnregistered, DetectorKind.Checksum),
        };

        ContentChunk chunk = MakeTextChunk("test");
        var result = await pipeline.ExecuteAsync(chunk, rules, detectors, CancellationToken.None);

        Assert.Empty(result.Candidates);
        Assert.NotEmpty(result.CoverageGaps);
        Assert.Contains(result.CoverageGaps, g => g.DetectorId == DetUnregistered);
    }
}
