using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.UnitTests.Rules;

public sealed class BaselinePolicyTests
{
    [Fact]
    public void Contains_exactly_eight_enabled_categories()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.Equal(
            Enumerable.Range(1, 8).Select(i => $"SENS-{i:000}"),
            baseline.Categories.Select(x => x.CategoryId.Value).Order(StringComparer.Ordinal));
        Assert.All(baseline.Categories, x => Assert.True(x.Enabled));
    }

    [Fact]
    public void Contains_exactly_eleven_registered_asset_policies()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.Equal(11, baseline.Assets.Select(x => x.AssetTypeId).Distinct().Count());
    }

    [Fact]
    public void Every_asset_includes_all_baseline_categories()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.All(baseline.Assets, asset =>
            Assert.Equal(8, asset.EffectiveCategoryIds(baseline.Categories).Count));
    }

    [Fact]
    public void Baseline_passes_graph_validation()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        RuleGraphValidator.GraphValidationResult result = RuleGraphValidator.Validate(baseline);
        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void Categories_are_all_SENS_001_through_008()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        var expected = Enumerable.Range(1, 8)
            .Select(i => $"SENS-{i:000}")
            .ToHashSet(StringComparer.Ordinal);
        Assert.All(baseline.Categories, c => Assert.Contains(c.CategoryId.Value, expected));
        Assert.Equal(8, baseline.Categories.Count);
    }

    [Fact]
    public void Each_category_has_non_empty_name_and_description()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.All(baseline.Categories, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Name),
                $"Category {c.CategoryId.Value} has empty name.");
            Assert.False(string.IsNullOrWhiteSpace(c.Description),
                $"Category {c.CategoryId.Value} has empty description.");
        });
    }

    [Fact]
    public void Each_asset_has_non_empty_name_and_description()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        Assert.All(baseline.Assets, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Name),
                $"Asset {a.AssetTypeId.Value} has empty name.");
            Assert.False(string.IsNullOrWhiteSpace(a.Description),
                $"Asset {a.AssetTypeId.Value} has empty description.");
        });
    }

    [Fact]
    public void Asset_007_has_knowledge_base_compliance_rule()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        var asset007 = baseline.Assets.Single(a => a.AssetTypeId.Value == "ASSET-007");
        Assert.NotEmpty(asset007.ComplianceRules);
        Assert.Contains(asset007.ComplianceRules,
            cr => cr.EvidenceField == "knowledge_base_transformed"
                  && cr.RequiredStatus == "verified");
    }

    [Fact]
    public void Asset_008_has_model_finetune_compliance_rule()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        var asset008 = baseline.Assets.Single(a => a.AssetTypeId.Value == "ASSET-008");
        Assert.NotEmpty(asset008.ComplianceRules);
        Assert.Contains(asset008.ComplianceRules,
            cr => cr.EvidenceField == "model_finetuned"
                  && cr.RequiredStatus == "verified");
    }

    [Fact]
    public void Baseline_roundtrip_serialization()
    {
        RulePackDocument baseline = BaselineFixture.Load();
        string json = baseline.ToJson();
        RulePackDocument roundTripped = RulePackDocument.Load(json);

        Assert.Equal(baseline.Categories.Count, roundTripped.Categories.Count);
        Assert.Equal(baseline.Assets.Count, roundTripped.Assets.Count);
        Assert.Equal(baseline.SchemaVersion, roundTripped.SchemaVersion);

        // Verify categories match
        foreach (var (orig, rt) in baseline.Categories.Zip(roundTripped.Categories))
        {
            Assert.Equal(orig.CategoryId, rt.CategoryId);
            Assert.Equal(orig.Name, rt.Name);
            Assert.Equal(orig.Enabled, rt.Enabled);
        }
    }
}
