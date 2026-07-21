using System.Collections.Frozen;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Result from a single chunk pipeline execution.
/// </summary>
public sealed record PipelineResult
{
    public IReadOnlyList<DetectionCandidate> Candidates { get; init; } = Array.Empty<DetectionCandidate>();
    public IReadOnlyList<DetectorCoverageGap> CoverageGaps { get; init; } = Array.Empty<DetectorCoverageGap>();
}

/// <summary>
/// Records when a detector could not run (exception or unregistered) —
/// this is a coverage gap, not a safe outcome.
/// </summary>
public sealed record DetectorCoverageGap
{
    public DetectorKind DetectorKind { get; init; }
    public DetectorId DetectorId { get; init; } = new("DET-UNKNOWN");
    public RuleId RuleId { get; init; } = new("RULE-UNKNOWN");
    public string Reason { get; init; } = string.Empty;
}

/// <summary>
/// Executes detectors in a fixed stage order against a content chunk.
/// Detector exceptions create coverage gaps and do not treat the chunk as safe.
/// Cancellation stops after the current bounded detector operation.
/// Results are deduplicated by (JobId, VirtualPath, SourceLocator, RuleId, DetectorId).
/// </summary>
public sealed class DetectorPipeline
{
    /// <summary>
    /// Fixed stage order matching the detection pipeline specification.
    /// </summary>
    public static readonly IReadOnlyList<DetectorKind> StageOrder = new[]
    {
        DetectorKind.StructuredField,
        DetectorKind.KnownFormat,
        DetectorKind.Checksum,
        DetectorKind.NetworkAddress,
        DetectorKind.Dictionary,
        DetectorKind.EntropyWithContext,
        DetectorKind.LicenseFingerprint,
        DetectorKind.ContentFingerprint,
        DetectorKind.SemanticCandidate,
    };

    private readonly FrozenDictionary<DetectorKind, IDetector> _detectors;

    public DetectorPipeline(IEnumerable<IDetector> detectors)
    {
        ArgumentNullException.ThrowIfNull(detectors);

        var map = new Dictionary<DetectorKind, IDetector>();
        foreach (IDetector det in detectors)
        {
            map[det.Kind] = det;
        }

        _detectors = map.ToFrozenDictionary();
    }

    /// <summary>
    /// Execute the pipeline for a single chunk.
    /// </summary>
    /// <param name="chunk">The content chunk to scan.</param>
    /// <param name="applicableRules">
    /// Rules that apply to this chunk, pre-filtered by asset type.
    /// Only enabled rules are processed.
    /// </param>
    /// <param name="detectorDefinitions">
    /// All detector definitions keyed by DetectorId.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<PipelineResult> ExecuteAsync(
        ContentChunk chunk,
        IReadOnlyList<RuleDefinition> applicableRules,
        IReadOnlyDictionary<DetectorId, DetectorDefinition> detectorDefinitions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        ArgumentNullException.ThrowIfNull(applicableRules);
        ArgumentNullException.ThrowIfNull(detectorDefinitions);

        var candidates = new List<DetectionCandidate>();
        var gaps = new List<DetectorCoverageGap>();
        var seenKeys = new HashSet<string>(StringComparer.Ordinal);

        // Group rules by detector kind, respecting stage order
        var rulesByStage = new Dictionary<DetectorKind, List<(RuleDefinition Rule, DetectorDefinition Detector)>>();

        foreach (RuleDefinition rule in applicableRules)
        {
            if (!rule.Enabled) continue;

            if (!detectorDefinitions.TryGetValue(rule.DetectorId, out DetectorDefinition? detDef))
            {
                gaps.Add(new DetectorCoverageGap
                {
                    DetectorKind = DetectorKind.KnownFormat, // unknown kind
                    DetectorId = rule.DetectorId,
                    RuleId = rule.Id,
                    Reason = $"Detector {rule.DetectorId.Value} not found in definitions."
                });
                continue;
            }

            if (!rulesByStage.ContainsKey(detDef.Kind))
                rulesByStage[detDef.Kind] = [];

            rulesByStage[detDef.Kind].Add((rule, detDef));
        }

        // Execute detectors in stage order
        foreach (DetectorKind stage in StageOrder)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!rulesByStage.TryGetValue(stage, out var ruleDetectorPairs))
                continue;

            if (!_detectors.TryGetValue(stage, out IDetector? detector))
            {
                foreach (var (rule, detDef) in ruleDetectorPairs)
                {
                    gaps.Add(new DetectorCoverageGap
                    {
                        DetectorKind = stage,
                        DetectorId = detDef.Id,
                        RuleId = rule.Id,
                        Reason = $"No detector registered for {stage}."
                    });
                }

                continue;
            }

            foreach (var (rule, detDef) in ruleDetectorPairs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    IReadOnlyList<DetectionCandidate> raw = await detector.DetectAsync(
                        chunk, rule, detDef, cancellationToken);

                    int limit = detDef.MaxMatchesPerChunk;
                    int added = 0;
                    foreach (DetectionCandidate candidate in raw)
                    {
                        if (added >= limit) break;

                        string key = candidate.DedupKey(chunk.JobId, chunk.VirtualPath);
                        if (seenKeys.Add(key))
                        {
                            candidates.Add(candidate);
                            added++;
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    gaps.Add(new DetectorCoverageGap
                    {
                        DetectorKind = stage,
                        DetectorId = detDef.Id,
                        RuleId = rule.Id,
                        Reason = $"Detector threw: {ex.GetType().Name}: {ex.Message}"
                    });
                }
            }
        }

        return new PipelineResult
        {
            Candidates = candidates,
            CoverageGaps = gaps
        };
    }
}
