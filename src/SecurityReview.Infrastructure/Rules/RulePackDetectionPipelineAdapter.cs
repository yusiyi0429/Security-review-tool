using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;
using SecurityReview.RulePack.Packaging.Models;
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

        var detectors = new List<RuleDetector>(runtime.BaseDetectors);
        List<(string Name, string EntityId, string RuleId)> entityTerms =
            BuildEntityTerms(runtime.Package.RestrictedEntities, assetTypes);
        if (entityTerms.Count > 0)
        {
            detectors.Add(new RestrictedEntityDetector(entityTerms));
        }

        PipelineResult result = await new RuleDetectorPipeline(detectors)
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
            RuleDefinition? rule = applicableRules.FirstOrDefault(
                candidateRule => candidateRule.Id == candidate.RuleId);
            string categoryScope = rule?.CategoryId.Value
                ?? candidate.FindingKind.ToString();
            PlaceholderMatchResult placeholder = runtime.PlaceholderMatcher.Match(
                candidate.Value,
                candidate.RuleId.Value,
                categoryScope);
            if (placeholder.Disposition == PlaceholderDisposition.ApprovedExample)
            {
                continue;
            }

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

        var licenseAuthorizations = package.ThirdPartyLicenses
            .Where(IsCurrentlyValid)
            .Where(license => !string.IsNullOrWhiteSpace(license.LicenseId))
            .Select(license => new LicenseFingerprintDetector.LicenseAuthorization
            {
                LicenseId = license.LicenseId,
                AuthorizedAssetScope = "*",
                AuthorizedUntil = ParseOptionalDate(license.ValidUntil),
                AuthorizationId = license.EvidenceRef,
            })
            .ToArray();

        var fingerprints = package.ThirdPartyLicenses
            .Where(IsCurrentlyValid)
            .Select(TryBuildFingerprint)
            .Where(entry => entry is not null)
            .Cast<ContentFingerprintDetector.FingerprintEntry>()
            .ToArray();

        var detectors = new List<RuleDetector>
        {
            new StructuredFieldDetector(),
            new KnownFormatDetector(),
            new ChecksumDetector(),
            new NetworkAddressDetector(),
            new EntropyContextDetector(),
            new LicenseFingerprintDetector(licenseAuthorizations),
            new ContentFingerprintDetector(fingerprints, []),
        };

        var placeholderEntries = package.SecurityPlaceholders
            .Where(placeholder => string.Equals(
                placeholder.MatchType, "exact", StringComparison.OrdinalIgnoreCase))
            .Where(IsCurrentlyValid)
            .Where(placeholder => !string.IsNullOrWhiteSpace(placeholder.Value))
            .Select(placeholder => new ApprovedPlaceholderMatcher.PlaceholderEntry
            {
                PlaceholderId = placeholder.PlaceholderId,
                Value = placeholder.Value,
                ContextScope = string.IsNullOrWhiteSpace(placeholder.AllowedContext)
                    ? placeholder.CategoryId
                    : placeholder.AllowedContext,
                Expiry = ParseOptionalDate(placeholder.ValidUntil),
            })
            .ToArray();

        IReadOnlyDictionary<DetectorId, DetectorDefinition> definitions =
            package.Policy.Rules.Detectors.ToDictionary(
                detector => detector.Id,
                detector => detector);
        return new RuntimePipeline(
            package,
            detectors,
            definitions,
            new ApprovedPlaceholderMatcher(placeholderEntries));
    }

    private static List<(string Name, string EntityId, string RuleId)>
        BuildEntityTerms(
            IReadOnlyList<RestrictedEntityEntry> entities,
            IReadOnlyList<AssetTypeId> assetTypes)
    {
        var terms = new List<(string Name, string EntityId, string RuleId)>();
        foreach (RestrictedEntityEntry entity in entities)
        {
            if (!IsCurrentlyValid(entity)
                || !ScopeApplies(entity.AssetScope, assetTypes))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(entity.StandardName))
            {
                terms.Add((entity.StandardName, entity.EntityId, entity.CategoryId));
            }
            if (!string.IsNullOrWhiteSpace(entity.Variant))
            {
                terms.Add((entity.Variant, entity.EntityId, entity.CategoryId));
            }
        }

        return terms;
    }

    private static bool ScopeApplies(
        string scope,
        IReadOnlyList<AssetTypeId> assetTypes) =>
        string.IsNullOrWhiteSpace(scope)
        || scope is "*" or "all"
        || assetTypes.Any(type => string.Equals(
            type.Value, scope, StringComparison.OrdinalIgnoreCase));

    private static bool IsCurrentlyValid(SecurityPlaceholder entry) =>
        IsCurrentlyValid(entry.ValidFrom, entry.ValidUntil);

    private static bool IsCurrentlyValid(ThirdPartyLicense entry) =>
        IsCurrentlyValid(entry.ValidFrom, entry.ValidUntil);

    private static bool IsCurrentlyValid(RestrictedEntityEntry entry) =>
        IsCurrentlyValid(entry.ValidFrom, entry.ValidUntil);

    private static bool IsCurrentlyValid(string validFrom, string validUntil)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset? from = ParseOptionalDate(validFrom);
        DateTimeOffset? until = ParseOptionalDate(validUntil);
        return (!from.HasValue || from.Value <= now)
            && (!until.HasValue || until.Value > now);
    }

    private static DateTimeOffset? ParseOptionalDate(string value) =>
        DateTimeOffset.TryParse(
            value,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal,
            out DateTimeOffset parsed)
            ? parsed
            : null;

    private static ContentFingerprintDetector.FingerprintEntry? TryBuildFingerprint(
        ThirdPartyLicense license)
    {
        if (string.IsNullOrWhiteSpace(license.Fingerprint))
        {
            return null;
        }

        string[] parts = license.Fingerprint.Split(':', 2);
        string algorithm = parts.Length == 2 ? parts[0] : "sha256";
        string hash = parts.Length == 2 ? parts[1] : parts[0];
        if (hash.Length == 0 || !hash.All(Uri.IsHexDigit))
        {
            return null;
        }

        return new ContentFingerprintDetector.FingerprintEntry
        {
            FingerprintId = license.LicenseId,
            Algorithm = algorithm,
            HashValue = hash,
            ComponentName = license.SourceName,
        };
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
        IReadOnlyList<RuleDetector> BaseDetectors,
        IReadOnlyDictionary<DetectorId, DetectorDefinition> Detectors,
        ApprovedPlaceholderMatcher PlaceholderMatcher);
}
