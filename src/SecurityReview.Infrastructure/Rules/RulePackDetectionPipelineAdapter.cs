using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;
using RuleDetectorPipeline = SecurityReview.RulePack.Detection.DetectorPipeline;
using RuleDetector = SecurityReview.RulePack.Detection.IDetector;

namespace SecurityReview.Infrastructure.Rules;

/// <summary>
/// Adapts the signed rule-package detector pipeline to the scan orchestrator.
/// Runtime pipelines are cached by the package hash captured in each scan
/// snapshot, preserving deterministic policy across active-package changes.
/// </summary>
public sealed class RulePackDetectionPipelineAdapter : IDetectionPipeline
{
    private readonly ActiveRulePackRuntimeProvider _runtimeProvider;
    private readonly ConcurrentDictionary<string, Task<RuntimePipeline>> _pipelines =
        new(StringComparer.OrdinalIgnoreCase);

    public RulePackDetectionPipelineAdapter(
        ActiveRulePackRuntimeProvider runtimeProvider)
    {
        _runtimeProvider = runtimeProvider
            ?? throw new ArgumentNullException(nameof(runtimeProvider));
    }

    public async IAsyncEnumerable<DetectionCandidate> DetectAsync(
        ScanId scanId,
        JobId jobId,
        FileId fileId,
        string fileSha256,
        string virtualPath,
        string rulePackHash,
        IReadOnlyList<AssetTypeId> assetTypes,
        ContentChunk chunk,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        _ = scanId;
        _ = jobId;
        _ = fileId;
        _ = fileSha256;
        _ = virtualPath;

        RuntimePipeline runtime = await GetPipelineAsync(
                rulePackHash, cancellationToken)
            .ConfigureAwait(false);

        RuleDefinition[] applicableRules = runtime.Package.Policy.Rules.Rules
            .Where(rule => rule.Enabled && AppliesTo(rule, assetTypes))
            .ToArray();
        if (applicableRules.Length == 0)
        {
            yield break;
        }

        PipelineResult result = await runtime.Pipeline
            .ExecuteAsync(
                chunk,
                applicableRules,
                runtime.Detectors,
                cancellationToken)
            .ConfigureAwait(false);
        if (result.CoverageGaps.Count > 0)
        {
            throw new InvalidOperationException(
                "The active rule detector pipeline reported a coverage gap.");
        }

        foreach (DetectionCandidate candidate in result.Candidates)
        {
            yield return candidate;
        }
    }

    private async Task<RuntimePipeline> GetPipelineAsync(
        string rulePackHash,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackHash);
        string normalized = rulePackHash.ToLowerInvariant();
        Task<RuntimePipeline> loadTask = _pipelines.GetOrAdd(
            normalized,
            hash => BuildPipelineAsync(hash));
        return await loadTask.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<RuntimePipeline> BuildPipelineAsync(string rulePackHash)
    {
        LoadedRulePack package = await _runtimeProvider
            .GetByHashAsync(rulePackHash, CancellationToken.None)
            .ConfigureAwait(false);

        var entityTerms = new List<(string Name, string EntityId, string RuleId)>();
        foreach (var entity in package.RestrictedEntities)
        {
            if (!string.IsNullOrWhiteSpace(entity.StandardName))
            {
                entityTerms.Add((
                    entity.StandardName,
                    entity.EntityId,
                    entity.CategoryId));
            }
            if (!string.IsNullOrWhiteSpace(entity.Variant))
            {
                entityTerms.Add((
                    entity.Variant,
                    entity.EntityId,
                    entity.CategoryId));
            }
        }

        var detectors = new List<RuleDetector>
        {
            new StructuredFieldDetector(),
            new KnownFormatDetector(),
            new ChecksumDetector(),
            new NetworkAddressDetector(),
            new EntropyContextDetector(),
            new LicenseFingerprintDetector([]),
            new ContentFingerprintDetector([], []),
        };
        if (entityTerms.Count > 0)
        {
            detectors.Add(new RestrictedEntityDetector(entityTerms));
        }

        IReadOnlyDictionary<DetectorId, DetectorDefinition> definitions =
            package.Policy.Rules.Detectors.ToDictionary(
                detector => detector.Id,
                detector => detector);
        return new RuntimePipeline(
            package,
            new RuleDetectorPipeline(detectors),
            definitions);
    }

    private static bool AppliesTo(
        RuleDefinition rule,
        IReadOnlyList<AssetTypeId> assetTypes)
    {
        if (assetTypes.Count == 0)
        {
            return true;
        }

        return assetTypes.Any(rule.AppliesToAssets.Contains);
    }

    private sealed record RuntimePipeline(
        LoadedRulePack Package,
        RuleDetectorPipeline Pipeline,
        IReadOnlyDictionary<DetectorId, DetectorDefinition> Detectors);
}
