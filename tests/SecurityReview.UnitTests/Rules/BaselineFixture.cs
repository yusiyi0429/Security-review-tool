using System.Text.Json;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.UnitTests.Rules;

internal static class BaselineFixture
{
    private static RulePackDocument? _cached;

    public static RulePackDocument Load()
    {
        if (_cached is not null) return _cached;

        string baseDir = FindRulesDir();

        var categoriesDoc = JsonSerializer.Deserialize<BaselineCategoriesPayload>(
            File.ReadAllText(Path.Combine(baseDir, "categories.json")),
            CategoriesJsonContext.Default.BaselineCategoriesPayload)!;

        var assetsDoc = JsonSerializer.Deserialize<BaselineAssetsPayload>(
            File.ReadAllText(Path.Combine(baseDir, "assets.json")),
            AssetsJsonContext.Default.BaselineAssetsPayload)!;

        var doc = new RulePackDocument
        {
            Categories = categoriesDoc.Categories
                .Select(c => new CategoryDefinition
                {
                    CategoryId = Domain.Assets.CategoryId.Parse(c.CategoryId),
                    Name = c.Name,
                    Description = c.Description,
                    Enabled = c.Enabled
                })
                .ToList(),

            Assets = assetsDoc.Assets
                .Select(a => new AssetPolicy
                {
                    AssetTypeId = Domain.Assets.AssetTypeId.Parse(a.AssetTypeId),
                    Name = a.Name,
                    Description = a.Description,
                    FocusWeights = a.FocusWeights?
                        .ToDictionary(
                            kv => Domain.Assets.CategoryId.Parse(kv.Key),
                            kv => kv.Value)
                        ?? new Dictionary<Domain.Assets.CategoryId, double>(),
                    ComplianceRules = a.ComplianceRules?
                        .Select(cr => new ComplianceRule
                        {
                            Id = cr.Id,
                            AssetTypeId = Domain.Assets.AssetTypeId.Parse(cr.AssetTypeId),
                            Name = cr.Name,
                            Description = cr.Description,
                            EvidenceField = cr.EvidenceField,
                            RequiredStatus = cr.RequiredStatus
                        })
                        .ToList()
                        ?? new List<ComplianceRule>()
                })
                .ToList()
        };

        _cached = doc;
        return doc;
    }

    private static string FindRulesDir()
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "rules", "baseline");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException("rules/baseline directory not found above the working directory.");
    }
}

// Minimal DTOs for baseline JSON parsing (avoid coupling to RulePackDocument for fixtures)
internal sealed record BaselineCategoriesPayload(
    int SchemaVersion,
    List<BaselineCategoryDto> Categories);

internal sealed record BaselineCategoryDto(
    string CategoryId,
    string Name,
    string Description,
    bool Enabled);

internal sealed record BaselineAssetsPayload(
    int SchemaVersion,
    List<BaselineAssetDto> Assets);

internal sealed record BaselineAssetDto(
    string AssetTypeId,
    string Name,
    string Description,
    Dictionary<string, double>? FocusWeights,
    List<BaselineComplianceRuleDto>? ComplianceRules);

internal sealed record BaselineComplianceRuleDto(
    string Id,
    string AssetTypeId,
    string Name,
    string Description,
    string EvidenceField,
    string RequiredStatus);
