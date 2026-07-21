using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Policy;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.UnitTests.Rules;

public sealed class EffectivePolicyBuilderTests
{
    private const string PackageHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string DifferentPackageHash = "1111111111111111111111111111111111111111111111111111111111111111";

    private static RulePackDocument CreateMinimalBaseline()
    {
        // All 8 categories
        var categories = new List<CategoryDefinition>();
        for (int i = 1; i <= 8; i++)
        {
            categories.Add(new CategoryDefinition
            {
                CategoryId = CategoryId.Parse($"SENS-{i:000}"),
                Name = $"Category {i}",
                Description = $"Description for category {i}",
                Enabled = true,
            });
        }

        // 2 assets
        var assets = new List<AssetPolicy>
        {
            new()
            {
                AssetTypeId = AssetTypeId.Parse("ASSET-001"),
                Name = "Asset One",
                Description = "First test asset",
            },
            new()
            {
                AssetTypeId = AssetTypeId.Parse("ASSET-002"),
                Name = "Asset Two",
                Description = "Second test asset",
            },
        };

        // 2 detectors
        var detectors = new List<DetectorDefinition>
        {
            new()
            {
                Id = new DetectorId("DET-TEST-ONE"),
                Kind = DetectorKind.KnownFormat,
                ConfigId = "config-1",
            },
            new()
            {
                Id = new DetectorId("DET-TEST-TWO"),
                Kind = DetectorKind.Checksum,
                ConfigId = "config-2",
            },
        };

        // 2 rules
        var rules = new List<RuleDefinition>
        {
            new()
            {
                Id = new RuleId("RULE-TEST-ONE"),
                CategoryId = CategoryId.Parse("SENS-001"),
                Severity = Severity.High,
                DetectorId = new DetectorId("DET-TEST-ONE"),
                DetectorConfigId = "cfg-1",
                FindingKind = FindingKind.SensitiveContent,
                Confidence = DetectionConfidence.High,
                Enabled = true,
                AppliesToAssets = new HashSet<AssetTypeId>
                {
                    AssetTypeId.Parse("ASSET-001"),
                },
            },
            new()
            {
                Id = new RuleId("RULE-TEST-TWO"),
                CategoryId = CategoryId.Parse("SENS-002"),
                Severity = Severity.Medium,
                DetectorId = new DetectorId("DET-TEST-TWO"),
                DetectorConfigId = "cfg-2",
                FindingKind = FindingKind.SensitiveContent,
                Confidence = DetectionConfidence.High,
                Enabled = true,
                AppliesToAssets = new HashSet<AssetTypeId>
                {
                    AssetTypeId.Parse("ASSET-001"),
                    AssetTypeId.Parse("ASSET-002"),
                },
            },
        };

        return new RulePackDocument
        {
            Categories = categories,
            Assets = assets,
            Rules = rules,
            Detectors = detectors,
        };
    }

    [Fact]
    public void Baseline_has_all_8_categories()
    {
        RulePackDocument baseline = CreateMinimalBaseline();
        EffectivePolicy result = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: null,
            PackageHash, localHash: null);

        Assert.Equal(8, result.Rules.Categories.Count);
        Assert.All(result.Rules.Categories, c => Assert.True(c.Enabled));
        var expectedIds = Enumerable.Range(1, 8)
            .Select(i => $"SENS-{i:000}")
            .ToHashSet(StringComparer.Ordinal);
        Assert.All(result.Rules.Categories, c =>
            Assert.Contains(c.CategoryId.Value, expectedIds));
    }

    [Fact]
    public void Asset_filtering_only_includes_relevant_rules()
    {
        RulePackDocument baseline = CreateMinimalBaseline();
        var assetFilter = new HashSet<string>(StringComparer.Ordinal) { "ASSET-001" };

        EffectivePolicy result = EffectivePolicyBuilder.Build(
            baseline, assetFilter, localSupplementJson: null,
            PackageHash, localHash: null);

        // Both rules apply to ASSET-001, so both should be included
        Assert.Contains(result.Rules.Rules, r => r.Id.Value == "RULE-TEST-ONE");
        Assert.Contains(result.Rules.Rules, r => r.Id.Value == "RULE-TEST-TWO");
        Assert.Equal(2, result.Rules.Rules.Count);
    }

    [Fact]
    public void New_additive_rule_with_equal_severity_succeeds()
    {
        RulePackDocument baseline = CreateMinimalBaseline();
        string policyWithoutSupplement = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: null,
            PackageHash, localHash: null).PolicySha256;

        // Build local supplement: add a new rule RULE-TEST-NEW
        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors
                .Append(new DetectorDefinition
                {
                    Id = new DetectorId("DET-TEST-NEW"),
                    Kind = DetectorKind.Dictionary,
                    ConfigId = "config-new",
                }).ToList(),
            Rules = baseline.Rules
                .Append(new RuleDefinition
                {
                    Id = new RuleId("RULE-TEST-NEW"),
                    CategoryId = CategoryId.Parse("SENS-001"),
                    Severity = Severity.High,
                    DetectorId = new DetectorId("DET-TEST-NEW"),
                    DetectorConfigId = "cfg-new",
                    FindingKind = FindingKind.SensitiveContent,
                    Confidence = DetectionConfidence.High,
                    Enabled = true,
                    AppliesToAssets = new HashSet<AssetTypeId>
                    {
                        AssetTypeId.Parse("ASSET-001"),
                    },
                }).ToList(),
        };

        EffectivePolicy result = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
            PackageHash, localHash: null);

        Assert.Contains(result.Rules.Rules, r => r.Id.Value == "RULE-TEST-NEW");
        Assert.NotEqual(policyWithoutSupplement, result.PolicySha256);
    }

    [Fact]
    public void Local_supplement_disabling_rule_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    return r with { Enabled = false };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Local_supplement_lowering_severity_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    return r with { Severity = Severity.Medium };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
        Assert.Contains("severity", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Local_supplement_changing_detector_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    return r with { DetectorId = new DetectorId("DET-TEST-TWO") };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
        Assert.Contains("detector", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Local_supplement_removing_rule_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        // Omit RULE-TEST-ONE from the local supplement
        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules
                .Where(r => r.Id.Value != "RULE-TEST-ONE")
                .ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Local_supplement_disabling_category_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories.Select(c =>
            {
                if (c.CategoryId.Value == "SENS-001")
                {
                    return c with { Enabled = false };
                }

                return c;
            }).ToList(),
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules,
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("SENS-001", ex.Message, StringComparison.Ordinal);
        Assert.Contains("category", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Deterministic_policy_sha256()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        EffectivePolicy first = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: null,
            PackageHash, localHash: null);

        EffectivePolicy second = EffectivePolicyBuilder.Build(
            CreateMinimalBaseline(), assetIds: null, localSupplementJson: null,
            PackageHash, localHash: null);

        Assert.Equal(first.PolicySha256, second.PolicySha256);
    }

    [Fact]
    public void Different_package_hash_produces_different_policy_sha256()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        EffectivePolicy first = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: null,
            PackageHash, localHash: null);

        EffectivePolicy second = EffectivePolicyBuilder.Build(
            CreateMinimalBaseline(), assetIds: null, localSupplementJson: null,
            DifferentPackageHash, localHash: null);

        Assert.NotEqual(first.PolicySha256, second.PolicySha256);
    }

    [Fact]
    public void New_additive_detector_in_local_supplement_succeeds()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors
                .Append(new DetectorDefinition
                {
                    Id = new DetectorId("DET-TEST-THREE"),
                    Kind = DetectorKind.EntropyWithContext,
                    ConfigId = "config-3",
                }).ToList(),
            Rules = baseline.Rules,
        };

        EffectivePolicy result = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
            PackageHash, localHash: null);

        Assert.Contains(result.Rules.Detectors,
            d => d.Id.Value == "DET-TEST-THREE");
        Assert.Equal(3, result.Rules.Detectors.Count);
    }

    [Fact]
    public void New_additive_asset_in_local_supplement_succeeds()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets
                .Append(new AssetPolicy
                {
                    AssetTypeId = AssetTypeId.Parse("ASSET-003"),
                    Name = "Asset Three",
                    Description = "Third test asset",
                }).ToList(),
            Detectors = baseline.Detectors,
            Rules = baseline.Rules,
        };

        EffectivePolicy result = EffectivePolicyBuilder.Build(
            baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
            PackageHash, localHash: null);

        Assert.Contains(result.Rules.Assets,
            a => a.AssetTypeId.Value == "ASSET-003");
        Assert.Equal(3, result.Rules.Assets.Count);
    }

    [Fact]
    public void Local_supplement_changing_finding_kind_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    return r with { FindingKind = FindingKind.AssetCompliance };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
        Assert.Contains("FindingKind", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Local_supplement_changing_category_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    return r with
                    {
                        CategoryId = CategoryId.Parse("SENS-003"),
                    };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
        Assert.Contains("category", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Local_supplement_narrowing_asset_scope_throws()
    {
        RulePackDocument baseline = CreateMinimalBaseline();

        var localDoc = new RulePackDocument
        {
            Categories = baseline.Categories,
            Assets = baseline.Assets,
            Detectors = baseline.Detectors,
            Rules = baseline.Rules.Select(r =>
            {
                if (r.Id.Value == "RULE-TEST-ONE")
                {
                    // Narrow scope: removes ASSET-001, keeps only ASSET-002
                    return r with
                    {
                        AppliesToAssets = new HashSet<AssetTypeId>
                        {
                            AssetTypeId.Parse("ASSET-002"),
                        },
                    };
                }

                return r;
            }).ToList(),
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EffectivePolicyBuilder.Build(
                baseline, assetIds: null, localSupplementJson: localDoc.ToJson(),
                PackageHash, localHash: null));

        Assert.Contains("ASSET-001", ex.Message, StringComparison.Ordinal);
        Assert.Contains("RULE-TEST-ONE", ex.Message, StringComparison.Ordinal);
    }
}
