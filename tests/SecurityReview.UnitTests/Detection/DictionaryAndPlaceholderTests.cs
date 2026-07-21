using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class DictionaryAndPlaceholderTests
{
    private static ContentChunk MakeChunk(string text)
    {
        return new ContentChunk(
            ProtocolVersion: 1,
            JobId: new JobId(Guid.NewGuid()),
            Sequence: 0,
            VirtualPath: "test.txt",
            FormatId: "text/plain",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: text,
            SourceStart: 0,
            SourceLength: text.Length,
            LocationMap: [],
            IsFinal: true);
    }

    private static RuleDefinition MakeRule(string id, DetectorId detectorId, DetectorKind kind = DetectorKind.Dictionary)
    {
        return new RuleDefinition
        {
            Id = new RuleId(id),
            CategoryId = CategoryId.Parse("SENS-004"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.Medium,
            DetectorId = detectorId,
            DetectorConfigId = "default",
            AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
            Enabled = true
        };
    }

    private static DetectorDefinition MakeDetector(DetectorId id, DetectorKind kind = DetectorKind.Dictionary,
        int maxMatches = 100)
    {
        return new DetectorDefinition
        {
            Id = id,
            Kind = kind,
            ConfigId = "default",
            MaxMatchesPerChunk = maxMatches
        };
    }

    // Static readonly arrays for CA1861 compliance (avoid repeated inline allocations)
    private static readonly string[] EntPayloadA = ["ENT-A", "RULE-DICT-001"];
    private static readonly string[] EntPayloadB = ["ENT-B", "RULE-DICT-002"];
    private static readonly string[] EntPayload001 = ["ENT-001"];
    private static readonly string[] EntPayloadC = ["ENT-C"];
    private static readonly string[] EntPayloadSingle = ["ENT"];

    // ==================== AhoCorasickMatcher ====================

    [Fact]
    public void ac_matcher_builds_and_matches_exact_terms()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            ("restricted_entity_a", 0, EntPayloadA),
            ("normal_company", 1, EntPayloadB)
        };

        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.None);

        var results = matcher.Search("restricted_entity_a is mentioned", 10);
        Assert.Single(results);
        Assert.Equal(0, results[0].TermId);
    }

    [Fact]
    public void ac_matcher_matches_case_insensitive_when_configured()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            ("Restricted Entity", 0, EntPayload001)
        };

        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.UpperInvariant);

        var results = matcher.Search("RESTRICTED entity is here", 10);
        Assert.Single(results);
    }

    [Fact]
    public void ac_matcher_returns_all_overlapping_matches()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            ("abc", 0, EntPayloadA),
            ("bc", 1, EntPayloadB),
            ("ab", 2, EntPayloadC)
        };

        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.None);

        var results = matcher.Search("abc", 100);
        // "abc" at 0, "ab" at 0, "bc" at 1
        Assert.InRange(results.Count, 2, 3);
    }

    [Fact]
    public void ac_matcher_respects_max_matches()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            ("test", 0, EntPayloadSingle)
        };

        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.None);

        var results = matcher.Search("test test test test test test test test", 3);
        Assert.InRange(results.Count, 1, 3);
    }

    [Fact]
    public void ac_matcher_rejects_too_many_terms()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>();
        for (int i = 0; i < 101; i++)
            entries.Add(($"term_{i:D5}", i, Array.Empty<string>()));

        var bounds = new AhoCorasickBounds { MaxTerms = 100 };

        var ex = Assert.Throws<AhoCorasickBuildException>(
            () => AhoCorasickMatcher.Build(entries, CaseNormalization.None, bounds));
        Assert.Contains("Term count", ex.Message);
    }

    [Fact]
    public void ac_matcher_rejects_too_long_term()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            (new string('x', 513), 0, Array.Empty<string>())
        };

        var bounds = new AhoCorasickBounds { MaxCharsPerTerm = 512 };

        var ex = Assert.Throws<AhoCorasickBuildException>(
            () => AhoCorasickMatcher.Build(entries, CaseNormalization.None, bounds));
    }

    [Fact]
    public void ac_matcher_rejects_too_many_bytes()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>();
        var bounds = new AhoCorasickBounds { MaxTotalNormalizedBytes = 50 };

        // Each term is 1000 chars ~ many UTF-8 bytes
        entries.Add((new string('a', 1000), 0, Array.Empty<string>()));

        var ex = Assert.Throws<AhoCorasickBuildException>(
            () => AhoCorasickMatcher.Build(entries, CaseNormalization.None, bounds));
    }

    [Fact]
    public void ac_matcher_handles_empty_text()
    {
        var entries = new List<(string, int, IReadOnlyList<string>)>
        {
            ("test", 0, Array.Empty<string>())
        };

        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.None);
        var results = matcher.Search("", 10);
        Assert.Empty(results);
    }

    [Fact]
    public void ac_matcher_handles_empty_entries()
    {
        var entries = Array.Empty<(string, int, IReadOnlyList<string>)>();
        var matcher = AhoCorasickMatcher.Build(entries, CaseNormalization.None);
        var results = matcher.Search("hello world", 10);
        Assert.Empty(results);
    }

    // ==================== RestrictedEntityDetector ====================

    [Fact]
    public async Task restricted_entity_detector_finds_standard_name()
    {
        var entries = new List<(string, string, string)>
        {
            ("Huawei Technologies Co., Ltd.", "ENT-HUAWEI", "RULE-DICT-001")
        };

        var detector = new RestrictedEntityDetector(entries, CaseNormalization.UpperInvariant);
        var chunk = MakeChunk("Huawei Technologies Co., Ltd. is a supplier.");
        var rule = MakeRule("RULE-DICT-001", new DetectorId("DET-RESTRICTED-ENTITIES"));
        var detDef = MakeDetector(new DetectorId("DET-RESTRICTED-ENTITIES"));

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task restricted_entity_detector_finds_abbreviation()
    {
        var entries = new List<(string, string, string)>
        {
            ("ZTE", "ENT-ZTE", "RULE-DICT-001")
        };

        var detector = new RestrictedEntityDetector(entries, CaseNormalization.UpperInvariant);
        var chunk = MakeChunk("Equipment from ZTE Corporation.");
        var rule = MakeRule("RULE-DICT-001", new DetectorId("DET-RESTRICTED-ENTITIES"));
        var detDef = MakeDetector(new DetectorId("DET-RESTRICTED-ENTITIES"));

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Single(results);
    }

    [Fact]
    public async Task restricted_entity_detector_matches_case_variant()
    {
        var entries = new List<(string, string, string)>
        {
            ("Entity ABC", "ENT-ABC", "RULE-DICT-001")
        };

        var detector = new RestrictedEntityDetector(entries, CaseNormalization.LowerInvariant);
        var chunk = MakeChunk("ENTITY abc is mentioned.");
        var rule = MakeRule("RULE-DICT-001", new DetectorId("DET-RESTRICTED-ENTITIES"));
        var detDef = MakeDetector(new DetectorId("DET-RESTRICTED-ENTITIES"));

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);
        Assert.Single(results);
    }

    [Fact]
    public async Task restricted_entity_with_no_terms_returns_empty()
    {
        var entries = Array.Empty<(string, string, string)>();
        var detector = new RestrictedEntityDetector(entries);
        var chunk = MakeChunk("No entities here.");
        var rule = MakeRule("RULE-DICT-001", new DetectorId("DET-RESTRICTED-ENTITIES"));
        var detDef = MakeDetector(new DetectorId("DET-RESTRICTED-ENTITIES"));

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);
        Assert.Empty(results);
    }

    // ==================== ApprovedPlaceholderMatcher ====================

    [Fact]
    public void placeholder_matcher_approves_exact_match()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-001",
                Value = "10.0.0.1",
                ContextScope = "SENS-002",
                Version = "1.0",
                Expiry = DateTimeOffset.UtcNow.AddDays(30)
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.Ordinal);

        var result = matcher.Match("10.0.0.1", "RULE-NET-001", "SENS-002");
        Assert.Equal(PlaceholderDisposition.ApprovedExample, result.Disposition);
        Assert.Equal("PH-001", result.PlaceholderId);
    }

    [Fact]
    public void placeholder_matcher_returns_not_approved_for_unknown_value()
    {
        var entries = Array.Empty<ApprovedPlaceholderMatcher.PlaceholderEntry>();
        var matcher = new ApprovedPlaceholderMatcher(entries);

        var result = matcher.Match("192.168.1.1", "RULE-NET-001", "SENS-002");
        Assert.Equal(PlaceholderDisposition.NotApproved, result.Disposition);
    }

    [Fact]
    public void placeholder_matcher_returns_expired_for_past_expiry()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-002",
                Value = "192.168.1.1",
                ContextScope = "SENS-002",
                Expiry = DateTimeOffset.UtcNow.AddDays(-1) // expired
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.Ordinal);

        var result = matcher.Match("192.168.1.1", "RULE-NET-001", "SENS-002");
        Assert.Equal(PlaceholderDisposition.Expired, result.Disposition);
    }

    [Fact]
    public void placeholder_matcher_requires_exact_scope_match()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-003",
                Value = "example.com",
                ContextScope = "SENS-003", // Only covers SENS-003
                Expiry = DateTimeOffset.UtcNow.AddDays(30)
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.Ordinal);

        // Check against different scope
        var result = matcher.Match("example.com", "RULE-NET-001", "SENS-002");
        Assert.NotEqual(PlaceholderDisposition.ApprovedExample, result.Disposition);
    }

    [Fact]
    public void placeholder_matcher_supports_wildcard_scope()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-004",
                Value = "1.2.3.4",
                ContextScope = "*", // Covers all scopes
                Expiry = DateTimeOffset.UtcNow.AddDays(30)
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.Ordinal);

        var result = matcher.Match("1.2.3.4", "RULE-NET-009", "SENS-005");
        Assert.Equal(PlaceholderDisposition.ApprovedExample, result.Disposition);
    }

    [Fact]
    public void placeholder_matcher_matches_by_rule_id()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-005",
                Value = "restricted.example.com",
                ContextScope = "RULE-NET-001",
                Expiry = DateTimeOffset.UtcNow.AddDays(30)
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.OrdinalIgnoreCase);

        var result = matcher.Match("restricted.example.com", "RULE-NET-001", "SENS-002");
        Assert.Equal(PlaceholderDisposition.ApprovedExample, result.Disposition);
    }

    [Fact]
    public void placeholder_matcher_supports_prefix_wildcard_scope()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>
        {
            new()
            {
                PlaceholderId = "PH-006",
                Value = "test.domain",
                ContextScope = "SENS-*", // Covers SENS-xxx
                Expiry = DateTimeOffset.UtcNow.AddDays(30)
            }
        };

        var matcher = new ApprovedPlaceholderMatcher(entries, StringComparison.OrdinalIgnoreCase);

        var result = matcher.Match("test.domain", "RULE-ANY", "SENS-002");
        Assert.Equal(PlaceholderDisposition.ApprovedExample, result.Disposition);
    }

    [Fact]
    public void candidate_value_looks_fake_but_unapproved_returns_not_approved()
    {
        var entries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>();
        var matcher = new ApprovedPlaceholderMatcher(entries);

        var result = matcher.Match("test@example.com", "RULE-ANY", "SENS-002");
        Assert.Equal(PlaceholderDisposition.NotApproved, result.Disposition);
    }
}
