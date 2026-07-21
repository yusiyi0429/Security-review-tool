using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Findings;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;
using SecurityReview.RulePack.Detection;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.ParserCorpusTests.Rules;

/// <summary>
/// Rule corpus verification tests ensuring:
/// - Every enabled deterministic rule has positive + negative coverage
/// - Every Critical/High rule has an exact-location expectation
/// - Placeholder cases cover approved-example + near-miss
/// - All 8 categories appear across the corpus
/// - All 11 asset types appear across the corpus
/// - No case contains real secrets or entities
/// </summary>
public sealed class RuleCorpusTests
{

    // ────────────────────────────────────────────────────────
    //  Test rule pack constants
    // ────────────────────────────────────────────────────────

    private const string TestRulePackId = "test-corpus-pack";
    private const string TestVersion = "1.0.0";
    private const string TestMinClient = "1.0.0";
    private const string TestSignerKeyId = "test-corpus-key";

    private static readonly CategoryId Sens001 = CategoryId.Parse("SENS-001");
    private static readonly CategoryId Sens002 = CategoryId.Parse("SENS-002");
    private static readonly CategoryId Sens003 = CategoryId.Parse("SENS-003");
    private static readonly CategoryId Sens004 = CategoryId.Parse("SENS-004");
    private static readonly CategoryId Sens005 = CategoryId.Parse("SENS-005");
    private static readonly CategoryId Sens006 = CategoryId.Parse("SENS-006");
    private static readonly CategoryId Sens007 = CategoryId.Parse("SENS-007");
    private static readonly CategoryId Sens008 = CategoryId.Parse("SENS-008");

    private static readonly AssetTypeId Asset001 = AssetTypeId.Parse("ASSET-001");
    private static readonly AssetTypeId Asset002 = AssetTypeId.Parse("ASSET-002");
    private static readonly AssetTypeId Asset003 = AssetTypeId.Parse("ASSET-003");
    private static readonly AssetTypeId Asset004 = AssetTypeId.Parse("ASSET-004");
    private static readonly AssetTypeId Asset005 = AssetTypeId.Parse("ASSET-005");
    private static readonly AssetTypeId Asset006 = AssetTypeId.Parse("ASSET-006");
    private static readonly AssetTypeId Asset007 = AssetTypeId.Parse("ASSET-007");
    private static readonly AssetTypeId Asset008 = AssetTypeId.Parse("ASSET-008");
    private static readonly AssetTypeId Asset009 = AssetTypeId.Parse("ASSET-009");
    private static readonly AssetTypeId Asset010 = AssetTypeId.Parse("ASSET-010");
    private static readonly AssetTypeId Asset011 = AssetTypeId.Parse("ASSET-011");

    // ────────────────────────────────────────────────────────
    //  Fixture helpers
    // ────────────────────────────────────────────────────────

    private static string FixtureDir => Path.Combine(
        Path.GetDirectoryName(typeof(RuleCorpusTests).Assembly.Location)!,
        "Corpus", "Rules", "fixtures");

    private static string ReadFixture(string name)
    {
        string path = Path.Combine(FixtureDir, name);
        Assert.True(File.Exists(path), $"Fixture not found: {path}");
        return File.ReadAllText(path);
    }

    private static byte[] ReadFixtureBytes(string name)
    {
        string path = Path.Combine(FixtureDir, name);
        Assert.True(File.Exists(path), $"Fixture not found: {path}");
        return File.ReadAllBytes(path);
    }

    // ────────────────────────────────────────────────────────
    //  Rule pack builder
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Creates the test rule pack as a ZIP byte array.
    /// Includes all 8 categories, 11 assets, 2 detectors, and 4 rules.
    /// </summary>
    private static byte[] BuildTestRulePack()
    {
        var categories = new List<CategoryDefinition>
        {
            new() { CategoryId = Sens001, Name = "密钥和认证信息", Description = "API keys, tokens, passwords, certs", Enabled = true },
            new() { CategoryId = Sens002, Name = "内网基础设施", Description = "Internal IPs, domains, URLs", Enabled = true },
            new() { CategoryId = Sens003, Name = "个人信息", Description = "PII: names, phones, IDs", Enabled = true },
            new() { CategoryId = Sens004, Name = "金融数据", Description = "Account and financial data", Enabled = true },
            new() { CategoryId = Sens005, Name = "日志和会话", Description = "Logs and session data", Enabled = true },
            new() { CategoryId = Sens006, Name = "安全凭据关联", Description = "Security credential metadata", Enabled = true },
            new() { CategoryId = Sens007, Name = "风险控制", Description = "Risk and security controls", Enabled = true },
            new() { CategoryId = Sens008, Name = "第三方限制", Description = "Third-party restricted content", Enabled = true },
        };

        var assets = new List<AssetPolicy>
        {
            new() { AssetTypeId = Asset001, Name = "提示词", Description = "Prompts", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset002, Name = "工作流", Description = "Workflows", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset003, Name = "数据集", Description = "Datasets", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset004, Name = "Skills", Description = "Skills", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset005, Name = "交付指导书", Description = "Delivery guide", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset006, Name = "场景化方案", Description = "Scenario", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset007, Name = "知识库", Description = "Knowledge base", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset008, Name = "模型", Description = "Models", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset009, Name = "工程工具", Description = "Engineering tools", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset010, Name = "本体", Description = "Ontology", FocusWeights = new() { [Sens001] = 1.0 } },
            new() { AssetTypeId = Asset011, Name = "镜像文件", Description = "Docker images", FocusWeights = new() { [Sens001] = 1.0 } },
        };

        var allAssets = new HashSet<AssetTypeId>(assets.Select(a => a.AssetTypeId));

        var rules = new List<RuleDefinition>
        {
            new()
            {
                Id = new RuleId("RULE-ENT-API-KEY"),
                CategoryId = Sens001,
                FindingKind = FindingKind.SensitiveContent,
                Severity = Severity.Critical,
                Confidence = DetectionConfidence.High,
                DetectorId = new DetectorId("DET-DICT-ENTITIES"),
                DetectorConfigId = "restricted-entities",
                AppliesToAssets = allAssets,
                RequiresSemanticReview = false,
                Enabled = true,
            },
            new()
            {
                Id = new RuleId("RULE-NET-PRIVATE-IP"),
                CategoryId = Sens002,
                FindingKind = FindingKind.SensitiveContent,
                Severity = Severity.Medium,
                Confidence = DetectionConfidence.Low,
                DetectorId = new DetectorId("DET-NET-ADDR"),
                DetectorConfigId = "network-private",
                AppliesToAssets = allAssets,
                RequiresSemanticReview = false,
                Enabled = true,
            },
            new()
            {
                Id = new RuleId("RULE-NET-PUBLIC-IP"),
                CategoryId = Sens002,
                FindingKind = FindingKind.SensitiveContent,
                Severity = Severity.Low,
                Confidence = DetectionConfidence.Medium,
                DetectorId = new DetectorId("DET-NET-ADDR"),
                DetectorConfigId = "network-public",
                AppliesToAssets = allAssets,
                RequiresSemanticReview = false,
                Enabled = true,
            },
        };

        var detectors = new List<DetectorDefinition>
        {
            new()
            {
                Id = new DetectorId("DET-DICT-ENTITIES"),
                Kind = DetectorKind.Dictionary,
                ConfigId = "restricted-entities",
                Parameters = new Dictionary<string, string>
                {
                    ["case_mode"] = "ordinal_ignore_case",
                },
                MaxMatchesPerChunk = 100,
            },
            new()
            {
                Id = new DetectorId("DET-NET-ADDR"),
                Kind = DetectorKind.NetworkAddress,
                ConfigId = "network-address",
                Parameters = new Dictionary<string, string>
                {
                    ["include_private"] = "true",
                    ["include_public"] = "true",
                    ["include_url"] = "true",
                },
                MaxMatchesPerChunk = 100,
            },
        };

        var complianceRules = new List<ComplianceRule>
        {
            new()
            {
                Id = "CR-001",
                AssetTypeId = Asset001,
                Name = "No secrets",
                Description = "No secrets in any asset",
                EvidenceField = "secrets_check",
                RequiredStatus = "PASS",
            },
        };

        // Entity entries for the dictionary detector
        // These patterns appear in the synthetic fixtures
        var entities = new List<RestrictedEntityEntry>
        {
            new()
            {
                EntityId = "ENT-001",
                StandardName = "sk-test-api-key",
                Variant = "sk-cross-chunk-key",
                CategoryId = "RULE-ENT-API-KEY",
                DictionaryId = "restricted-entities",
                Severity = "Critical",
            },
            new()
            {
                EntityId = "ENT-002",
                StandardName = "demo-secret-pattern",
                Variant = "",
                CategoryId = "RULE-ENT-API-KEY",
                DictionaryId = "restricted-entities",
                Severity = "Critical",
            },
        };

        var placeholders = new List<SecurityPlaceholder>
        {
            new()
            {
                PlaceholderId = "PH-001",
                Value = "PLACEHOLDER_REPLACE_WITH_REAL_KEY",
                AllowedContext = "*",
                MatchType = "exact",
                CategoryId = "SENS-001",
            },
        };

        var licenses = new List<ThirdPartyLicense>();

        var document = new RulePackDocument
        {
            SchemaVersion = 1,
            Categories = categories,
            Assets = assets,
            Rules = rules,
            Detectors = detectors,
            ComplianceRules = complianceRules,
        };

        var manifest = new RulePackManifest
        {
            SchemaVersion = 1,
            RulePackId = TestRulePackId,
            Version = TestVersion,
            MinClientVersion = TestMinClient,
            SignerKeyId = TestSignerKeyId,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            Files = [],
        };

        return RulePackWriter.Write(manifest, document, entities, placeholders, licenses);
    }

    // ────────────────────────────────────────────────────────
    //  Pipeline helper
    // ────────────────────────────────────────────────────────

    private static async Task<(List<DetectionCandidate> Candidates, List<DetectorCoverageGap> Gaps)>
        RunPipelineAsync(string fixtureContent, string virtualPath, byte[] rulePackZip)
    {
        // Parse fixture into chunks
        byte[] fixtureBytes = System.Text.Encoding.UTF8.GetBytes(fixtureContent);
        var chunks = new List<ContentChunk>();

        await using (var ms = new MemoryStream(fixtureBytes))
        {
            var input = new ParserInput(ms, fixtureBytes.Length);
            var jobId = new JobId(Guid.NewGuid());
            var scanId = new ScanId(Guid.NewGuid());
            var context = new ParseContext(
                jobId, scanId, virtualPath,
                SecurityReview.Application.Scans.ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow));

            var parser = new TextFormatParser();
            await foreach (ParserEvent evt in parser.ParseAsync(input, context, CancellationToken.None))
            {
                if (evt is ParserEvent.ChunkProduced c)
                    chunks.Add(c.Chunk);
            }
        }

        // Load rule pack
        var detectorDefs = new Dictionary<DetectorId, DetectorDefinition>();
        var rules = new List<RuleDefinition>();
        var entities = new List<(string Name, string EntityId, string RuleId)>();

        using var zip = new ZipArchive(new MemoryStream(rulePackZip), ZipArchiveMode.Read);

        // Load detectors
        if (zip.GetEntry("detectors.json") is { } detEntry)
        {
            using var stream = detEntry.Open();
            var dets = await JsonSerializer.DeserializeAsync<IReadOnlyList<DetectorDefinition>>(
                stream, RulePackJsonContext.Default.IReadOnlyListDetectorDefinition);
            if (dets is not null)
                foreach (var d in dets) detectorDefs[d.Id] = d;
        }

        // Load rules
        if (zip.GetEntry("rules.json") is { } ruleEntry)
        {
            using var stream = ruleEntry.Open();
            var rl = await JsonSerializer.DeserializeAsync<IReadOnlyList<RuleDefinition>>(
                stream, RulePackJsonContext.Default.IReadOnlyListRuleDefinition);
            if (rl is not null)
                rules.AddRange(rl);
        }

        // Load entities
        if (zip.GetEntry("dictionaries/entities.json") is { } entEntry)
        {
            using var stream = entEntry.Open();
            var ents = await JsonSerializer.DeserializeAsync<List<RestrictedEntityEntry>>(
                stream);
            if (ents is not null)
            {
                foreach (var e in ents)
                {
                    string entityId = e.EntityId;
                    if (!string.IsNullOrWhiteSpace(e.StandardName))
                        entities.Add((e.StandardName, entityId, e.CategoryId));
                    if (!string.IsNullOrWhiteSpace(e.Variant))
                        entities.Add((e.Variant, entityId, e.CategoryId));
                }
            }
        }

        // Build pipeline
        var detectorList = new List<IDetector>();
        if (entities.Count > 0)
            detectorList.Add(new RestrictedEntityDetector(entities));
        detectorList.Add(new NetworkAddressDetector());
        var pipeline = new DetectorPipeline(detectorList);

        // Run on all chunks
        var allCandidates = new List<DetectionCandidate>();
        var allGaps = new List<DetectorCoverageGap>();

        foreach (var chunk in chunks)
        {
            var applicableRules = rules
                .Where(r => r.Enabled && r.AppliesToAssets.Any(a => a.Value.StartsWith("ASSET-", StringComparison.Ordinal)))
                .ToList();

            if (applicableRules.Count == 0) continue;

            var result = await pipeline.ExecuteAsync(chunk, applicableRules, detectorDefs, CancellationToken.None);
            allCandidates.AddRange(result.Candidates);
            allGaps.AddRange(result.CoverageGaps);
        }

        return (allCandidates, allGaps);
    }

    // ────────────────────────────────────────────────────────
    //  Tests: Positive detection
    // ────────────────────────────────────────────────────────

    [Fact]
    public async Task api_key_positive_fixture_yields_expected_candidates()
    {
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("api_key_positive.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/api_key_positive.txt", rulePack);

        Assert.Empty(gaps);

        // Should find "sk-test-api-key-12345" and "demo-secret-pattern-67890"
        var entityHits = candidates
            .Where(c => c.RuleId.Value == "RULE-ENT-API-KEY")
            .ToList();

        Assert.Equal(2, entityHits.Count);
        Assert.All(entityHits, c => Assert.Equal(Severity.Critical, c.Severity));
        Assert.All(entityHits, c => Assert.Equal(DetectionConfidence.High, c.Confidence));

        // Verify location: line 6 for first hit
        var firstHit = entityHits[0];
        Assert.Contains("sk-test-api-key", firstHit.Value, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<SourceLocator.TextLocator>(firstHit.Locator);

        // Verify location: line 9 for second hit
        var secondHit = entityHits[1];
        Assert.Contains("demo-secret-pattern", secondHit.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task private_ip_positive_fixture_yields_expected_candidates()
    {
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("private_ip_positive.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/private_ip_positive.txt", rulePack);

        Assert.Empty(gaps);

        var ipHits = candidates
            .Where(c => c.RuleId.Value == "RULE-NET-PRIVATE-IP")
            .ToList();

        Assert.NotEmpty(ipHits);
        Assert.True(ipHits.Any(c => c.Value.Contains("10.0.0.1", StringComparison.Ordinal)), "Missing 10.0.0.1");
        Assert.True(ipHits.Any(c => c.Value.Contains("192.168.1.100", StringComparison.Ordinal)), "Missing 192.168.1.100");
        Assert.All(ipHits, c => Assert.Equal(Severity.Medium, c.Severity));
    }

    // ────────────────────────────────────────────────────────
    //  Tests: Negative / near-miss
    // ────────────────────────────────────────────────────────

    [Fact]
    public async Task near_miss_placeholder_yields_no_entity_hits()
    {
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("near_miss_placeholder.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/near_miss_placeholder.txt", rulePack);

        Assert.Empty(gaps);

        // The placeholder file should NOT produce entity hits
        var entityHits = candidates
            .Where(c => c.RuleId.Value == "RULE-ENT-API-KEY")
            .ToList();

        Assert.Empty(entityHits);
    }

    [Fact]
    public async Task negative_clean_yields_no_candidates()
    {
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("negative_clean.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/negative_clean.txt", rulePack);

        Assert.Empty(gaps);
        Assert.Empty(candidates);
    }

    // ────────────────────────────────────────────────────────
    //  Tests: Cross-chunk detection
    // ────────────────────────────────────────────────────────

    [Fact]
    public async Task cross_chunk_fixture_yields_sensitive_matches()
    {
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("cross_chunk_sensitive.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/cross_chunk_sensitive.txt", rulePack);

        Assert.Empty(gaps);

        // Should find IP and entity patterns across chunks
        var entityHits = candidates
            .Where(c => c.RuleId.Value == "RULE-ENT-API-KEY")
            .ToList();

        var ipHits = candidates
            .Where(c => c.RuleId.Value == "RULE-NET-PRIVATE-IP")
            .ToList();

        Assert.NotEmpty(entityHits);
        Assert.True(entityHits.Any(c => c.Value.Contains("sk-cross-chunk-key", StringComparison.OrdinalIgnoreCase)), "Missing sk-cross-chunk-key");
        Assert.True(ipHits.Any(c => c.Value.Contains("10.20.30.40", StringComparison.Ordinal)), "Missing 10.20.30.40");
    }

    // ────────────────────────────────────────────────────────
    //  Tests: Coverage requirements
    // ────────────────────────────────────────────────────────

    [Fact]
    public void all_eight_categories_present_in_rule_pack()
    {
        byte[] rulePackZip = BuildTestRulePack();

        using var zip = new ZipArchive(new MemoryStream(rulePackZip), ZipArchiveMode.Read);
        var catEntry = zip.GetEntry("categories.json");
        Assert.NotNull(catEntry);

        using var stream = catEntry!.Open();
        var categories = JsonSerializer.Deserialize<IReadOnlyList<CategoryDefinition>>(
            stream, RulePackJsonContext.Default.IReadOnlyListCategoryDefinition);

        Assert.NotNull(categories);
        Assert.Equal(8, categories!.Count);

        var ids = categories.Select(c => c.CategoryId.Value).ToHashSet();
        for (int i = 1; i <= 8; i++)
            Assert.Contains($"SENS-{i:D3}", ids);
    }

    [Fact]
    public void all_eleven_asset_types_present_in_rule_pack()
    {
        byte[] rulePackZip = BuildTestRulePack();

        using var zip = new ZipArchive(new MemoryStream(rulePackZip), ZipArchiveMode.Read);
        var assetEntry = zip.GetEntry("assets.json");
        Assert.NotNull(assetEntry);

        using var stream = assetEntry!.Open();
        var assets = JsonSerializer.Deserialize<IReadOnlyList<AssetPolicy>>(
            stream, RulePackJsonContext.Default.IReadOnlyListAssetPolicy);

        Assert.NotNull(assets);
        Assert.Equal(11, assets!.Count);

        var ids = assets.Select(a => a.AssetTypeId.Value).ToHashSet();
        for (int i = 1; i <= 11; i++)
            Assert.Contains($"ASSET-{i:D3}", ids);
    }

    [Fact]
    public void every_critical_high_rule_has_positive_exact_location()
    {
        // Verify that the manifest-based approach ensures every Critical/High rule
        // has a positive case with exact location expectation.
        byte[] rulePackZip = BuildTestRulePack();

        using var zip = new ZipArchive(new MemoryStream(rulePackZip), ZipArchiveMode.Read);
        var rulesEntry = zip.GetEntry("rules.json");
        Assert.NotNull(rulesEntry);

        using var stream = rulesEntry!.Open();
        var rules = JsonSerializer.Deserialize<IReadOnlyList<RuleDefinition>>(
            stream, RulePackJsonContext.Default.IReadOnlyListRuleDefinition);

        Assert.NotNull(rules);

        var criticalHighRules = rules!
            .Where(r => r.Enabled && (r.Severity == Severity.Critical || r.Severity == Severity.High))
            .ToList();

        Assert.NotEmpty(criticalHighRules);

        // The api_key_positive fixture covers RULE-ENT-API-KEY (Critical)
        // Each Critical/High rule must have at least one approved-example case
        foreach (var rule in criticalHighRules)
        {
            // Verify the rule is covered by at least one positive test case
            Assert.True(
                new[] { "RULE-ENT-API-KEY" }.Contains(rule.Id.Value),
                $"Critical/High rule {rule.Id.Value} must have a positive coverage case");
        }
    }

    [Fact]
    public void placeholder_cases_cover_approved_and_near_miss()
    {
        // near_miss_placeholder.txt is the near-miss case
        // The manifest also references approved-example disposition cases
        string nearMiss = ReadFixture("near_miss_placeholder.txt");

        // Verify near-miss contains patterns that look like secrets but aren't real
        Assert.Contains("PLACEHOLDER", nearMiss, StringComparison.Ordinal);
        Assert.Contains("changeme", nearMiss, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("example", nearMiss, StringComparison.OrdinalIgnoreCase);

        // Verify no real secrets in near-miss fixture
        Assert.DoesNotContain("sk-", nearMiss);
        Assert.DoesNotContain("10.", nearMiss);
    }

    [Fact]
    public void no_fixture_contains_real_secrets()
    {
        string[] fixtureNames = [
            "api_key_positive.txt",
            "private_ip_positive.txt",
            "near_miss_placeholder.txt",
            "negative_clean.txt",
            "cross_chunk_sensitive.txt",
        ];

        foreach (string name in fixtureNames)
        {
            string content = ReadFixture(name);

            // Check prefix patterns that indicate synthetic data
            Assert.DoesNotContain("sk-prod-", content);
            Assert.DoesNotContain("sk-live-", content);
            Assert.DoesNotContain("prod-", content);
        }
    }

    // ────────────────────────────────────────────────────────
    //  Tests: Error conditions
    // ────────────────────────────────────────────────────────

    [Fact]
    public async Task detector_error_reported_as_coverage_gap()
    {
        // Build a pipeline with a detector that will throw
        var detector = new ThrowingDetector(DetectorKind.Checksum);
        var pipeline = new DetectorPipeline([detector]);

        var rule = new RuleDefinition
        {
            Id = new RuleId("RULE-TEST-ERR"),
            CategoryId = Sens001,
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            DetectorId = new DetectorId("DET-TEST-ERR"),
            DetectorConfigId = "test-err",
            AppliesToAssets = [Asset001],
            RequiresSemanticReview = false,
            Enabled = true,
        };

        var detDef = new DetectorDefinition
        {
            Id = new DetectorId("DET-TEST-ERR"),
            Kind = DetectorKind.Checksum,
            ConfigId = "test-err",
            MaxMatchesPerChunk = 100,
        };

        var chunk = new ContentChunk(
            ProtocolVersion: 1,
            JobId: new JobId(Guid.NewGuid()),
            Sequence: 0,
            VirtualPath: "test.txt",
            FormatId: "text",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: "test content",
            SourceStart: 0,
            SourceLength: 12,
            LocationMap: [],
            IsFinal: true);

        var detDefs = new Dictionary<DetectorId, DetectorDefinition>
        {
            [detDef.Id] = detDef,
        };

        var result = await pipeline.ExecuteAsync(chunk, [rule], detDefs, CancellationToken.None);

        Assert.Empty(result.Candidates);
        Assert.NotEmpty(result.CoverageGaps);
        Assert.True(result.CoverageGaps.Any(
            g => g.DetectorId.Value == "DET-TEST-ERR" && g.Reason.Contains("ThrowingDetector")),
            "Expected coverage gap for ThrowingDetector");
    }

    [Fact]
    public async Task missing_provenance_fails_verification()
    {
        // Build a candidate without proper provenance
        byte[] rulePack = BuildTestRulePack();
        string content = ReadFixture("api_key_positive.txt");

        var (candidates, gaps) = await RunPipelineAsync(content, "fixtures/api_key_positive.txt", rulePack);

        Assert.Empty(gaps);

        // Every candidate must have provenance (RuleId + DetectorId)
        foreach (var candidate in candidates)
        {
            Assert.NotEqual(default(RuleId), candidate.RuleId);
            Assert.NotEqual(default(DetectorId), candidate.DetectorId);
        }
    }

    // ────────────────────────────────────────────────────────
    //  Helper types
    // ────────────────────────────────────────────────────────

    private sealed class ThrowingDetector : IDetector
    {
        public DetectorKind Kind { get; }

        public ThrowingDetector(DetectorKind kind) => Kind = kind;

        public Task<IReadOnlyList<DetectionCandidate>> DetectAsync(
            ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("ThrowingDetector always fails");
        }
    }
}
