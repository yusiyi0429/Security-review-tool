using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Normalization;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePack.Policy;

/// <summary>
/// Builds an <see cref="EffectivePolicy"/> by merging a signed baseline with
/// asset-filtered rules, compliance rules, and optional local additive entries.
/// Local supplements are rejected entirely if any entry weakens the baseline.
/// </summary>
public static class EffectivePolicyBuilder
{
    /// <summary>
    /// Builds the effective policy from a baseline document, active asset IDs,
    /// optional local supplement, and package identity.
    /// </summary>
    /// <param name="baseline">The signed baseline rule pack document.</param>
    /// <param name="assetIds">Asset type IDs to include. If empty or null, all baseline assets are included.</param>
    /// <param name="localSupplementJson">Optional local additive supplement as JSON RulePackDocument.</param>
    /// <param name="packageHash">SHA-256 of the active package ZIP.</param>
    /// <param name="localHash">SHA-256 of the local supplement file, or null.</param>
    /// <exception cref="InvalidOperationException">Thrown when local supplement weakens the baseline.</exception>
    public static EffectivePolicy Build(
        RulePackDocument baseline,
        IReadOnlySet<string>? assetIds,
        string? localSupplementJson,
        string packageHash,
        string? localHash)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(packageHash);

        var warnings = new List<string>();
        var activeAssetIds = assetIds is { Count: > 0 }
            ? assetIds.ToFrozenSet(StringComparer.Ordinal)
            : baseline.Assets.Select(a => a.AssetTypeId.Value).ToFrozenSet(StringComparer.Ordinal);

        // Start with baseline rules and categories (all categories always present)
        var mergedCategories = baseline.Categories.ToList();
        var mergedAssets = baseline.Assets.ToList();
        var mergedDetectors = baseline.Detectors.ToList();
        var mergedComplianceRules = baseline.ComplianceRules.ToList();

        // Filter rules to active asset IDs
        var mergedRules = baseline.Rules
            .Where(r => r.AppliesToAssets.Any(a => activeAssetIds.Contains(a.Value)))
            .ToList();

        // Merge local supplement
        RulePackDocument? localDoc = null;
        if (!string.IsNullOrWhiteSpace(localSupplementJson))
        {
            try
            {
                localDoc = RulePackDocument.Load(localSupplementJson);
                warnings.Add("Local additive supplement is active.");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "Local supplement is invalid and cannot be applied.", ex);
            }
        }

        if (localDoc is not null)
        {
            MergeLocalSupplement(
                baseline, localDoc, mergedRules, mergedCategories, mergedAssets,
                mergedDetectors, mergedComplianceRules, activeAssetIds);
        }

        // Build the final document (normalized)
        var finalDoc = new RulePackDocument
        {
            Categories = mergedCategories
                .OrderBy(c => c.CategoryId.Value, StringComparer.Ordinal)
                .ToList(),
            Assets = mergedAssets
                .OrderBy(a => a.AssetTypeId.Value, StringComparer.Ordinal)
                .ToList(),
            Rules = mergedRules
                .OrderBy(r => r.Id.Value, StringComparer.Ordinal)
                .ToList(),
            Detectors = mergedDetectors
                .OrderBy(d => d.Id.Value, StringComparer.Ordinal)
                .ToList(),
            ComplianceRules = mergedComplianceRules
                .OrderBy(cr => cr.Id, StringComparer.Ordinal)
                .ToList(),
        };

        finalDoc = RulePackNormalizer.Normalize(finalDoc);

        // Compute detector versions
        var detectorVersions = finalDoc.Detectors
            .ToDictionary(
                d => d.Id.Value,
                d => d.ConfigId,
                StringComparer.Ordinal);

        // Compute policy SHA-256
        string policySha256 = ComputePolicySha256(
            finalDoc, packageHash, localHash, activeAssetIds, detectorVersions);

        return new EffectivePolicy
        {
            Rules = finalDoc,
            PolicySha256 = policySha256,
            PackageSha256 = packageHash,
            LocalSupplementHash = localHash,
            ActiveAssetIds = activeAssetIds,
            ActiveDetectorVersions = detectorVersions.AsReadOnly(),
            Warnings = warnings,
        };
    }

    private static void MergeLocalSupplement(
        RulePackDocument baseline,
        RulePackDocument local,
        List<RuleDefinition> mergedRules,
        List<CategoryDefinition> mergedCategories,
        List<AssetPolicy> mergedAssets,
        List<DetectorDefinition> mergedDetectors,
        List<ComplianceRule> mergedComplianceRules,
        FrozenSet<string> activeAssetIds)
    {
        // Build baseline lookup maps
        var baselineRulesById = baseline.Rules
            .ToDictionary(r => r.Id.Value, StringComparer.Ordinal);
        var baselineCategoriesById = baseline.Categories
            .ToDictionary(c => c.CategoryId.Value, StringComparer.Ordinal);
        var baselineAssetsById = baseline.Assets
            .ToDictionary(a => a.AssetTypeId.Value, StringComparer.Ordinal);
        var baselineDetectorsById = baseline.Detectors
            .ToDictionary(d => d.Id.Value, StringComparer.Ordinal);
        var baselineComplianceById = baseline.ComplianceRules
            .ToDictionary(cr => cr.Id, StringComparer.Ordinal);

        // Check categories: cannot disable baseline categories
        foreach (var localCat in local.Categories)
        {
            if (baselineCategoriesById.TryGetValue(localCat.CategoryId.Value, out var baselineCat))
            {
                if (!localCat.Enabled && baselineCat.Enabled)
                {
                    throw new InvalidOperationException(
                        $"Local supplement cannot disable baseline category '{localCat.CategoryId.Value}'.");
                }
            }
        }

        // Check for removed categories (categories in baseline not in local — that's OK, local is additive)
        // But if local has fewer categories than baseline, reject
        if (local.Categories.Count < baseline.Categories.Count)
        {
            var missing = baseline.Categories
                .Select(c => c.CategoryId.Value)
                .Except(local.Categories.Select(c => c.CategoryId.Value), StringComparer.Ordinal)
                .ToList();
            if (missing.Count > 0)
            {
                throw new InvalidOperationException(
                    $"Local supplement cannot remove baseline categories: {string.Join(", ", missing)}.");
            }
        }

        // Check rules: cannot weaken baseline rules
        foreach (var localRule in local.Rules)
        {
            if (baselineRulesById.TryGetValue(localRule.Id.Value, out var baselineRule))
            {
                // Existing rule — must not weaken
                ValidateRuleNotWeakened(baselineRule, localRule);
            }
            else
            {
                // New rule — additive, allowed
                // Ensure it targets active asset IDs
                if (localRule.AppliesToAssets.Any(a => activeAssetIds.Contains(a.Value)))
                {
                    mergedRules.Add(localRule);
                }
            }
        }

        // Check that no baseline rules are removed
        foreach (var baselineRule in baseline.Rules)
        {
            if (!local.Rules.Any(r =>
                string.Equals(r.Id.Value, baselineRule.Id.Value, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    $"Local supplement cannot remove baseline rule '{baselineRule.Id.Value}'.");
            }
        }

        // Merge new categories (additive only)
        foreach (var localCat in local.Categories)
        {
            if (!baselineCategoriesById.ContainsKey(localCat.CategoryId.Value))
            {
                mergedCategories.Add(localCat);
            }
        }

        // Merge new assets (additive only)
        foreach (var localAsset in local.Assets)
        {
            if (!baselineAssetsById.ContainsKey(localAsset.AssetTypeId.Value))
            {
                mergedAssets.Add(localAsset);
            }
        }

        // Merge new detectors (additive only)
        foreach (var localDet in local.Detectors)
        {
            if (!baselineDetectorsById.ContainsKey(localDet.Id.Value))
            {
                mergedDetectors.Add(localDet);
            }
        }

        // Merge new compliance rules (additive only)
        foreach (var localCr in local.ComplianceRules)
        {
            if (!baselineComplianceById.ContainsKey(localCr.Id))
            {
                mergedComplianceRules.Add(localCr);
            }
        }
    }

    private static void ValidateRuleNotWeakened(RuleDefinition baseline, RuleDefinition local)
    {
        // Cannot disable rule
        if (baseline.Enabled && !local.Enabled)
        {
            throw new InvalidOperationException(
                $"Local supplement cannot disable baseline rule '{baseline.Id.Value}'.");
        }

        // Cannot lower severity
        if (local.Severity > baseline.Severity)
        {
            throw new InvalidOperationException(
                $"Local supplement cannot lower severity of rule '{baseline.Id.Value}' " +
                $"from {baseline.Severity} to {local.Severity}.");
        }

        // Cannot change detector
        if (!string.Equals(local.DetectorId.Value, baseline.DetectorId.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Local supplement cannot change detector of rule '{baseline.Id.Value}' " +
                $"from '{baseline.DetectorId.Value}' to '{local.DetectorId.Value}'.");
        }

        // Cannot change category
        if (!string.Equals(local.CategoryId.Value, baseline.CategoryId.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Local supplement cannot change category of rule '{baseline.Id.Value}' " +
                $"from '{baseline.CategoryId.Value}' to '{local.CategoryId.Value}'.");
        }

        // Cannot change finding kind
        if (local.FindingKind != baseline.FindingKind)
        {
            throw new InvalidOperationException(
                $"Local supplement cannot change FindingKind of rule '{baseline.Id.Value}' " +
                $"from {baseline.FindingKind} to {local.FindingKind}.");
        }

        // Cannot change detector config (tighten only)
        if (!string.Equals(local.DetectorConfigId, baseline.DetectorConfigId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Local supplement cannot change DetectorConfigId of rule '{baseline.Id.Value}' " +
                $"from '{baseline.DetectorConfigId}' to '{local.DetectorConfigId}'.");
        }

        // Cannot reduce asset scope
        foreach (var baselineAsset in baseline.AppliesToAssets)
        {
            if (!local.AppliesToAssets.Contains(baselineAsset))
            {
                throw new InvalidOperationException(
                    $"Local supplement cannot remove asset '{baselineAsset.Value}' " +
                    $"from rule '{baseline.Id.Value}'.");
            }
        }

        // Severity can be equal or higher; changes above baseline are allowed
    }

    private static string ComputePolicySha256(
        RulePackDocument doc,
        string packageHash,
        string? localHash,
        IReadOnlySet<string> assetIds,
        IReadOnlyDictionary<string, string> detectorVersions)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();

        writer.WriteStartArray("asset_ids");
        foreach (var id in assetIds.Order(StringComparer.Ordinal))
        {
            writer.WriteStringValue(id);
        }
        writer.WriteEndArray();

        writer.WriteStartArray("categories");
        foreach (var cat in doc.Categories.OrderBy(c => c.CategoryId.Value, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("category_id", cat.CategoryId.Value);
            writer.WriteString("name", cat.Name);
            writer.WriteBoolean("enabled", cat.Enabled);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WriteStartArray("compliance_rules");
        foreach (var cr in doc.ComplianceRules.OrderBy(c => c.Id, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("id", cr.Id);
            writer.WriteString("asset_type_id", cr.AssetTypeId.Value);
            writer.WriteString("evidence_field", cr.EvidenceField);
            writer.WriteString("required_status", cr.RequiredStatus);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WriteStartObject("detector_versions");
        foreach (var kv in detectorVersions.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            writer.WriteString(kv.Key, kv.Value);
        }
        writer.WriteEndObject();

        if (localHash is not null)
            writer.WriteString("local_hash", localHash);
        else
            writer.WriteNull("local_hash");

        writer.WriteString("package_hash", packageHash);

        writer.WriteStartArray("rules");
        foreach (var rule in doc.Rules.OrderBy(r => r.Id.Value, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("rule_id", rule.Id.Value);
            writer.WriteString("category_id", rule.CategoryId.Value);
            writer.WriteString("severity", rule.Severity.ToString());
            writer.WriteString("detector_id", rule.DetectorId.Value);
            writer.WriteString("detector_config_id", rule.DetectorConfigId);
            writer.WriteString("finding_kind", rule.FindingKind.ToString());
            writer.WriteBoolean("enabled", rule.Enabled);
            writer.WriteStartArray("applies_to_assets");
            foreach (var a in rule.AppliesToAssets.OrderBy(a => a.Value, StringComparer.Ordinal))
            {
                writer.WriteStringValue(a.Value);
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WriteEndObject();
        writer.Flush();

        byte[] jsonBytes = stream.ToArray();
        string sha256 = Convert.ToHexStringLower(SHA256.HashData(jsonBytes));

        return sha256;
    }
}
