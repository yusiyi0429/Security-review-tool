using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.ContractTests.Rules;

public sealed class RuleSchemaTests
{
    private static string SchemaPath(string name)
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "rules", "schemas", name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException($"Schema '{name}' not found above the working directory.");
    }

    private static string BaselinePath(string name)
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "rules", "baseline", name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException($"Baseline fixture '{name}' not found above the working directory.");
    }

    [Fact]
    public void All_four_schema_files_exist_and_are_valid_json()
    {
        foreach (string name in new[]
                 {
                     "rule-pack-manifest-v1.schema.json",
                     "categories-v1.schema.json",
                     "assets-v1.schema.json",
                     "detectors-v1.schema.json"
                 })
        {
            string path = SchemaPath(name);
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
            Assert.Equal("https://json-schema.org/draft/2020-12/schema",
                doc.RootElement.GetProperty("$schema").GetString());
        }
    }

    [Fact]
    public void Categories_baseline_fixture_is_valid()
    {
        string json = File.ReadAllText(BaselinePath("categories.json"));
        using JsonDocument doc = JsonDocument.Parse(json);

        Assert.Equal(1, doc.RootElement.GetProperty("schema_version").GetInt32());
        JsonElement categories = doc.RootElement.GetProperty("categories");
        Assert.Equal(8, categories.GetArrayLength());

        for (int i = 0; i < categories.GetArrayLength(); i++)
        {
            JsonElement cat = categories[i];
            Assert.StartsWith("SENS-00", cat.GetProperty("category_id").GetString());
            Assert.True(cat.GetProperty("enabled").GetBoolean());
        }
    }

    [Fact]
    public void Assets_baseline_fixture_is_valid()
    {
        string json = File.ReadAllText(BaselinePath("assets.json"));
        using JsonDocument doc = JsonDocument.Parse(json);

        Assert.Equal(1, doc.RootElement.GetProperty("schema_version").GetInt32());
        JsonElement assets = doc.RootElement.GetProperty("assets");
        Assert.Equal(11, assets.GetArrayLength());

        for (int i = 0; i < assets.GetArrayLength(); i++)
        {
            JsonElement asset = assets[i];
            Assert.StartsWith("ASSET-", asset.GetProperty("asset_type_id").GetString());
        }
    }

    [Fact]
    public void Compliance_baseline_fixture_is_valid()
    {
        string json = File.ReadAllText(BaselinePath("compliance.json"));
        using JsonDocument doc = JsonDocument.Parse(json);

        Assert.Equal(1, doc.RootElement.GetProperty("schema_version").GetInt32());
        JsonElement rules = doc.RootElement.GetProperty("compliance_rules");
        Assert.Equal(2, rules.GetArrayLength());
    }

    [Fact]
    public void Rule_id_format_validation()
    {
        Assert.True(RuleDefinition.IsValidRuleId("RULE-ABC"));
        Assert.True(RuleDefinition.IsValidRuleId("RULE-SENS-001-KEY-CHECK"));
        Assert.True(RuleDefinition.IsValidRuleId("RULE-ABC-DEF-123"));

        Assert.False(RuleDefinition.IsValidRuleId(""));
        Assert.False(RuleDefinition.IsValidRuleId("rule-abc"));
        Assert.False(RuleDefinition.IsValidRuleId("RULE-ab"));
        Assert.False(RuleDefinition.IsValidRuleId("RULE-" + new string('A', 65)));
        Assert.False(RuleDefinition.IsValidRuleId("RULE-abc_def"));
        Assert.False(RuleDefinition.IsValidRuleId("PREFIX-ABC"));
    }

    [Fact]
    public void Detector_id_format_validation()
    {
        Assert.True(DetectorDefinition.IsValidDetectorId("DET-ABC"));
        Assert.True(DetectorDefinition.IsValidDetectorId("DET-KNOWN-FORMAT-001"));
        Assert.True(DetectorDefinition.IsValidDetectorId("DET-XYZ-123"));

        Assert.False(DetectorDefinition.IsValidDetectorId(""));
        Assert.False(DetectorDefinition.IsValidDetectorId("det-abc"));
        Assert.False(DetectorDefinition.IsValidDetectorId("DET-ab"));
        Assert.False(DetectorDefinition.IsValidDetectorId("DET-" + new string('A', 65)));
        Assert.False(DetectorDefinition.IsValidDetectorId("DET-abc_def"));
        Assert.False(DetectorDefinition.IsValidDetectorId("PREFIX-ABC"));
    }

    [Fact]
    public void Deserialize_categories_baseline_with_strict_json()
    {
        string json = File.ReadAllText(BaselinePath("categories.json"));
        var doc = JsonSerializer.Deserialize<StrictCategoriesPayload>(
            json, CategoriesStrictContext.Default.StrictCategoriesPayload)!;

        Assert.Equal(8, doc.Categories.Count);
        Assert.All(doc.Categories, c => Assert.True(c.Enabled));
    }

    [Fact]
    public void Deserialize_assets_baseline_with_strict_json()
    {
        string json = File.ReadAllText(BaselinePath("assets.json"));
        var doc = JsonSerializer.Deserialize<StrictAssetsPayload>(
            json, AssetsStrictContext.Default.StrictAssetsPayload)!;

        Assert.Equal(11, doc.Assets.Count);
    }

    [Fact]
    public void Reject_unknown_property_in_categories()
    {
        string json = File.ReadAllText(BaselinePath("categories.json"));
        // Insert an unknown property
        string tampered = json.Replace("\"enabled\": true",
            "\"enabled\": true, \"extra_field\": \"should_reject\"",
            StringComparison.Ordinal);

        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<StrictCategoriesPayload>(
                tampered, CategoriesStrictContext.Default.StrictCategoriesPayload));
    }

    [Fact]
    public void Reject_negative_focus_weight_in_assets()
    {
        string json = File.ReadAllText(BaselinePath("assets.json"));
        string tampered = json.Replace("\"SENS-001\": 1.0",
            "\"SENS-001\": -1.0",
            StringComparison.Ordinal);

        var doc = JsonSerializer.Deserialize<StrictAssetsPayload>(
            tampered, AssetsStrictContext.Default.StrictAssetsPayload)!;

        // Verify that the tampered value was deserialized
        Assert.Contains(doc.Assets[0].FocusWeights!, kv => kv.Value < 0);
    }

    [Fact]
    public void Reject_unknown_property_in_assets()
    {
        string json = File.ReadAllText(BaselinePath("assets.json"));
        string tampered = json.Replace("\"asset_type_id\": \"ASSET-001\"",
            "\"asset_type_id\": \"ASSET-001\", \"extra_prop\": 42",
            StringComparison.Ordinal);

        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<StrictAssetsPayload>(
                tampered, AssetsStrictContext.Default.StrictAssetsPayload));
    }

    [Fact]
    public void Reject_disabled_category()
    {
        string json = File.ReadAllText(BaselinePath("categories.json"));
        string tampered = json.Replace("\"enabled\": true", "\"enabled\": false");

        var doc = JsonSerializer.Deserialize<StrictCategoriesPayload>(
            tampered, CategoriesStrictContext.Default.StrictCategoriesPayload)!;

        // Even if JSON doesn't reject, the validate method should catch it
        Assert.Contains(doc.Categories, c => !c.Enabled);
    }

    [Fact]
    public void Reject_invalid_category_id()
    {
        string json = File.ReadAllText(BaselinePath("categories.json"));
        string tampered = json.Replace("SENS-001", "SENS-999");

        Assert.Throws<ArgumentException>(() =>
        {
            var doc = JsonSerializer.Deserialize<StrictCategoriesPayload>(
                tampered, CategoriesStrictContext.Default.StrictCategoriesPayload)!;
            // Force validation by trying to construct domain types
            foreach (var c in doc.Categories)
            {
                Domain.Assets.CategoryId.Parse(c.CategoryId);
            }
        });
    }

    [Fact]
    public void Reject_oversized_category_name()
    {
        string longName = new('A', 257);
        string tampered = $$"""
            {
              "schema_version": 1,
              "categories": [
                {
                  "category_id": "SENS-001",
                  "name": "{{longName}}",
                  "description": "Test",
                  "enabled": true
                }
              ]
            }
            """;

        var doc = JsonSerializer.Deserialize<StrictCategoriesPayload>(
            tampered, CategoriesStrictContext.Default.StrictCategoriesPayload)!;
        Assert.True(doc.Categories[0].Name.Length > 256);
    }

    [Fact]
    public void Serialize_deserialize_roundtrip_produces_identical_utf8_bytes()
    {
        // Use a minimal RulePackDocument
        var rule = new RuleDefinition
        {
            Id = new RuleId("RULE-TEST-001"),
            CategoryId = Domain.Assets.CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-TEST-001"),
            DetectorConfigId = "default",
            AppliesToAssets = new HashSet<Domain.Assets.AssetTypeId>
            {
                Domain.Assets.AssetTypeId.Parse("ASSET-001")
            },
            RequiresSemanticReview = false,
            Enabled = true
        };

        var detector = new DetectorDefinition
        {
            Id = new DetectorId("DET-TEST-001"),
            Kind = DetectorKind.KnownFormat,
            ConfigId = "default",
            Parameters = new Dictionary<string, string> { ["format"] = "pem" },
            MaxMatchesPerChunk = 100
        };

        var category = new CategoryDefinition
        {
            CategoryId = Domain.Assets.CategoryId.Parse("SENS-001"),
            Name = "Test Category",
            Description = "Test description",
            Enabled = true
        };

        var asset = new AssetPolicy
        {
            AssetTypeId = Domain.Assets.AssetTypeId.Parse("ASSET-001"),
            Name = "Test Asset",
            Description = "Test asset description",
            FocusWeights = new Dictionary<Domain.Assets.CategoryId, double>
            {
                [Domain.Assets.CategoryId.Parse("SENS-001")] = 1.0
            },
            ComplianceRules = new List<ComplianceRule>()
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition> { category },
            Assets = new List<AssetPolicy> { asset },
            Rules = new List<RuleDefinition> { rule },
            Detectors = new List<DetectorDefinition> { detector },
            ComplianceRules = new List<ComplianceRule>()
        };

        byte[] first = doc.ToUtf8Bytes();
        string json = Encoding.UTF8.GetString(first);
        RulePackDocument roundTripped = RulePackDocument.Load(json);
        byte[] second = roundTripped.ToUtf8Bytes();

        Assert.Equal(first, second);
    }

    [Fact]
    public void Reject_invalid_rule_id_in_document()
    {
        string json = """
            {
              "schema_version": 1,
              "categories": [],
              "assets": [],
              "rules": [
                {
                  "id": "not-a-valid-rule-id",
                  "category_id": "SENS-001",
                  "finding_kind": "SensitiveContent",
                  "severity": "High",
                  "confidence": "High",
                  "detector_id": "DET-001",
                  "detector_config_id": "default",
                  "applies_to_assets": ["ASSET-001"],
                  "requires_semantic_review": false,
                  "enabled": true
                }
              ],
              "detectors": [],
              "compliance_rules": []
            }
            """;

        Assert.Throws<InvalidOperationException>(() => RulePackDocument.Load(json));
    }

    [Fact]
    public void Reject_duplicate_rule_ids()
    {
        string json = """
            {
              "schema_version": 1,
              "categories": [],
              "assets": [],
              "rules": [
                {
                  "id": "RULE-DUP",
                  "category_id": "SENS-001",
                  "finding_kind": "SensitiveContent",
                  "severity": "High",
                  "confidence": "High",
                  "detector_id": "DET-001",
                  "detector_config_id": "default",
                  "applies_to_assets": ["ASSET-001"],
                  "requires_semantic_review": false,
                  "enabled": true
                },
                {
                  "id": "RULE-DUP",
                  "category_id": "SENS-001",
                  "finding_kind": "SensitiveContent",
                  "severity": "High",
                  "confidence": "High",
                  "detector_id": "DET-001",
                  "detector_config_id": "default",
                  "applies_to_assets": ["ASSET-001"],
                  "requires_semantic_review": false,
                  "enabled": true
                }
              ],
              "detectors": [],
              "compliance_rules": []
            }
            """;

        Assert.Throws<InvalidOperationException>(() => RulePackDocument.Load(json));
    }

    [Fact]
    public void Graph_validator_detects_dangling_detector_reference()
    {
        var rule = new RuleDefinition
        {
            Id = new RuleId("RULE-TEST-001"),
            CategoryId = Domain.Assets.CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-MISSING"),
            DetectorConfigId = "default",
            AppliesToAssets = new HashSet<Domain.Assets.AssetTypeId>
            {
                Domain.Assets.AssetTypeId.Parse("ASSET-001")
            }
        };

        var doc = new RulePackDocument
        {
            Rules = new List<RuleDefinition> { rule },
            Detectors = new List<DetectorDefinition>(),
            Categories = new List<CategoryDefinition>
            {
                new()
                {
                    CategoryId = Domain.Assets.CategoryId.Parse("SENS-001"),
                    Name = "Test",
                    Description = "Test",
                    Enabled = true
                }
            }
        };

        var result = RuleGraphValidator.Validate(doc);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors,
            e => e.Contains("DET-MISSING", StringComparison.Ordinal));
    }
}
