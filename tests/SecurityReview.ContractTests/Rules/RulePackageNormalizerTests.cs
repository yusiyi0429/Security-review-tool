using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Normalization;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.ContractTests.Rules;

public sealed class RulePackageNormalizerTests
{
    [Fact]
    public void Sort_by_ordinal_id()
    {
        var cat3 = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-003"),
            Name = "Category 3",
            Description = "",
            Enabled = true,
        };
        var cat1 = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-001"),
            Name = "Category 1",
            Description = "",
            Enabled = true,
        };
        var cat2 = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-002"),
            Name = "Category 2",
            Description = "",
            Enabled = true,
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition> { cat3, cat1, cat2 },
        };

        var normalized = RulePackNormalizer.Normalize(doc);

        Assert.Equal("SENS-001", normalized.Categories[0].CategoryId.Value);
        Assert.Equal("SENS-002", normalized.Categories[1].CategoryId.Value);
        Assert.Equal("SENS-003", normalized.Categories[2].CategoryId.Value);
    }

    [Fact]
    public void Sort_rules_by_rule_id()
    {
        var ruleZ = new RuleDefinition
        {
            Id = new RuleId("RULE-ZETA"),
            CategoryId = CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-TEST-001"),
        };
        var ruleA = new RuleDefinition
        {
            Id = new RuleId("RULE-ALPHA"),
            CategoryId = CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-TEST-001"),
        };
        var ruleM = new RuleDefinition
        {
            Id = new RuleId("RULE-MIDDLE"),
            CategoryId = CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-TEST-001"),
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition>
            {
                new()
                {
                    CategoryId = CategoryId.Parse("SENS-001"),
                    Name = "Test",
                    Description = "",
                    Enabled = true,
                },
            },
            Rules = new List<RuleDefinition> { ruleZ, ruleA, ruleM },
            Detectors = new List<DetectorDefinition>
            {
                new()
                {
                    Id = new DetectorId("DET-TEST-001"),
                    Kind = DetectorKind.KnownFormat,
                },
            },
        };

        var normalized = RulePackNormalizer.Normalize(doc);

        Assert.Equal("RULE-ALPHA", normalized.Rules[0].Id.Value);
        Assert.Equal("RULE-MIDDLE", normalized.Rules[1].Id.Value);
        Assert.Equal("RULE-ZETA", normalized.Rules[2].Id.Value);
    }

    [Fact]
    public void Sort_detectors_by_detector_id()
    {
        var det3 = new DetectorDefinition
        {
            Id = new DetectorId("DET-003"),
            Kind = DetectorKind.KnownFormat,
        };
        var det1 = new DetectorDefinition
        {
            Id = new DetectorId("DET-001"),
            Kind = DetectorKind.KnownFormat,
        };
        var det2 = new DetectorDefinition
        {
            Id = new DetectorId("DET-002"),
            Kind = DetectorKind.KnownFormat,
        };

        var doc = new RulePackDocument
        {
            Detectors = new List<DetectorDefinition> { det3, det2, det1 },
        };

        var normalized = RulePackNormalizer.Normalize(doc);

        Assert.Equal("DET-001", normalized.Detectors[0].Id.Value);
        Assert.Equal("DET-002", normalized.Detectors[1].Id.Value);
        Assert.Equal("DET-003", normalized.Detectors[2].Id.Value);
    }

    [Fact]
    public void Normalize_preserves_all_properties()
    {
        var cat = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-001"),
            Name = "Test Name",
            Description = "A long description",
            Enabled = true,
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition> { cat },
        };

        var normalized = RulePackNormalizer.Normalize(doc);

        var single = Assert.Single(normalized.Categories);
        Assert.Equal("SENS-001", single.CategoryId.Value);
        Assert.Equal("Test Name", single.Name);
        Assert.Equal("A long description", single.Description);
        Assert.True(single.Enabled);
    }

    [Fact]
    public void Normalize_handles_empty_collections()
    {
        var doc = new RulePackDocument();

        var normalized = RulePackNormalizer.Normalize(doc);

        Assert.Empty(normalized.Categories);
        Assert.Empty(normalized.Assets);
        Assert.Empty(normalized.Rules);
        Assert.Empty(normalized.Detectors);
        Assert.Empty(normalized.ComplianceRules);
    }
}
