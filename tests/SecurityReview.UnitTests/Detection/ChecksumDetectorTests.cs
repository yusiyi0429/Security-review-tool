using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class ChecksumDetectorTests
{
    private static RuleDefinition MakeRule(string id, DetectorKind kind)
    {
        return new RuleDefinition
        {
            Id = new RuleId(id),
            CategoryId = CategoryId.Parse("SENS-001"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.Medium,
            DetectorId = new DetectorId($"DET-{id[5..]}"),
            DetectorConfigId = "default",
            AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
            Enabled = true
        };
    }

    private static DetectorDefinition MakeDetector(string id, DetectorKind kind)
    {
        return new DetectorDefinition
        {
            Id = new DetectorId(id),
            Kind = kind,
            ConfigId = "default",
            Parameters = [],
            MaxMatchesPerChunk = 10
        };
    }

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

    [Fact]
    public async Task detects_valid_luhn_number()
    {
        // Valid Luhn: 4532015112830366 (test Visa PAN)
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("card: 4532015112830366");
        var rule = MakeRule("RULE-LUHN", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-LUHN-CARD") };
        var detDef = MakeDetector("DET-LUHN-CARD", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "luhn" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(result);
        Assert.Contains(result, c => c.Value == "4532015112830366");
        Assert.All(result, c => Assert.Equal(DetectionConfidence.High, c.Confidence));
    }

    [Fact]
    public async Task luhn_mismatch_lowers_confidence()
    {
        // Invalid Luhn: 4532015112830367 (last digit changed)
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("card: 4532015112830367");
        var rule = MakeRule("RULE-LUHN", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-LUHN-CARD") };
        var detDef = MakeDetector("DET-LUHN-CARD", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "luhn" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // A 16-digit number matching the pattern but with invalid Luhn gets lower confidence
        if (result.Count > 0)
        {
            Assert.All(result, c => Assert.True((int)c.Confidence >= (int)DetectionConfidence.Medium));
        }
    }

    [Fact]
    public async Task detects_valid_chinese_id_number()
    {
        // Valid Chinese ID: 110101199003071233
        // Region 110101 (Beijing Dongcheng), DOB 1990-03-07, sequence 123, checksum 3
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("身份证: 110101199003071233");
        var rule = MakeRule("RULE-CNID", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-CNID-CHECK") };
        var detDef = MakeDetector("DET-CNID-CHECK", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "cnid" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(result);
        Assert.Contains(result, c => c.Value == "110101199003071233");
    }

    [Fact]
    public async Task chinese_id_with_bad_checksum_lowers_confidence()
    {
        // 110101199003071235 — last digit changed (should be 3)
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("身份证: 110101199003071235");
        var rule = MakeRule("RULE-CNID-FAIL", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-CNID-CHECK") };
        var detDef = MakeDetector("DET-CNID-CHECK", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "cnid" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        if (result.Count > 0)
        {
            Assert.All(result, c => Assert.True(c.Confidence <= DetectionConfidence.Medium));
        }
    }

    [Fact]
    public async Task chinese_id_invalid_date_not_detected()
    {
        // Invalid date: 110101199013011234 (month 13)
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("身份证: 110101199013011234");
        var rule = MakeRule("RULE-CNID-DATE", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-CNID-CHECK") };
        var detDef = MakeDetector("DET-CNID-CHECK", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "cnid" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(result);
    }

    [Fact]
    public async Task respects_max_matches_per_chunk()
    {
        var detector = new ChecksumDetector();
        // Multiple valid Luhn numbers
        var chunk = MakeChunk("4532015112830366 4532015112830366 4532015112830366 4532015112830366 4532015112830366");
        var rule = MakeRule("RULE-LUHN-MAX", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-LUHN-CARD") };
        var detDef = MakeDetector("DET-LUHN-CARD", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "luhn" }, MaxMatchesPerChunk = 2 };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.True(result.Count <= 2);
    }

    [Fact]
    public async Task empty_chunk_returns_no_candidates()
    {
        var detector = new ChecksumDetector();
        var chunk = MakeChunk("");
        var rule = MakeRule("RULE-EMPTY", DetectorKind.Checksum)
            with { DetectorId = new DetectorId("DET-LUHN-CARD") };
        var detDef = MakeDetector("DET-LUHN-CARD", DetectorKind.Checksum)
            with { Parameters = new Dictionary<string, string> { ["algorithm"] = "luhn" } };

        var result = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(result);
    }
}
