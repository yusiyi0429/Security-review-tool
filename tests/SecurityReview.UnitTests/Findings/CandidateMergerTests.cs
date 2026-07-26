using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Findings;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Infrastructure.Cryptography;

namespace SecurityReview.UnitTests.Findings;

public sealed class CandidateMergerTests
{
    private static readonly ScanId ScanId = new(Guid.NewGuid());
    private static readonly JobId JobId = new(Guid.NewGuid());

    private static SourceLocator.TextLocator L(long line, long col, long byteStart, long byteLen) =>
        new(line, col, byteStart, byteLen);

    private static DetectionCandidate MakeCandidate(
        string value,
        SourceLocator? locator = null,
        string ruleId = "RULE-001",
        string detectorId = "DET-001",
        Severity severity = Severity.High,
        DetectionConfidence confidence = DetectionConfidence.High,
        FindingKind kind = FindingKind.SensitiveContent,
        bool requiresSemantic = false)
    {
        return DetectionCandidate.Create(
            value, "ctx", locator ?? L(1, 1, 0, 5),
            new RuleId(ruleId), new DetectorId(detectorId),
            severity, confidence, kind, requiresSemantic);
    }

    // ---------- Same value at multiple locations → one group, multiple occurrences ----------

    [Fact]
    public void Same_value_at_three_locations_becomes_one_group_with_three_occurrences()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", L(1, 1, 0, 5)),
            MakeCandidate("secret-abc", L(2, 1, 10, 5)),
            MakeCandidate("secret-abc", L(3, 1, 20, 5)),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.Equal(3, groups[0].Occurrences.Count);
        Assert.All(groups[0].Occurrences, o => Assert.Equal(groups[0].Id, o.GroupId));
    }

    // ---------- Different normalized values never merge ----------

    [Fact]
    public void Different_values_produce_separate_groups()
    {
        var candidates = new[]
        {
            MakeCandidate("value-alpha"),
            MakeCandidate("value-beta"),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Equal(2, groups.Count);
        Assert.NotEqual(groups[0].Id, groups[1].Id);
    }

    [Fact]
    public void Same_value_with_different_finding_kinds_produces_separate_groups()
    {
        DetectionCandidate[] candidates =
        [
            MakeCandidate("same-value", kind: FindingKind.SensitiveContent),
            MakeCandidate("same-value", kind: FindingKind.AssetCompliance),
        ];

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        IReadOnlyList<FindingGroup> groups = merger.Merge(
            ScanId,
            JobId,
            candidates,
            "file-sha256",
            "file.txt");

        Assert.Equal(2, groups.Count);
        Assert.Contains(groups, group =>
            group.FindingKind == FindingKind.SensitiveContent);
        Assert.Contains(groups, group =>
            group.FindingKind == FindingKind.AssetCompliance);
    }

    [Fact]
    public void Whitespace_casing_differences_do_not_merge_with_real_fingerprint()
    {
        var candidates = new[]
        {
            MakeCandidate("  Secret-ABC  "),
            MakeCandidate("secret-abc"),
        };

        using var svc = new EphemeralValueFingerprintService();
        var merger = new CandidateMerger(svc);
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");
        Assert.Single(groups);
    }

    // ---------- Same location/rule from chunk overlap → single occurrence ----------

    [Fact]
    public void Same_location_and_rule_from_chunk_overlap_becomes_one_occurrence()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", L(1, 1, 0, 5), "RULE-001"),
            MakeCandidate("secret-abc", L(1, 1, 0, 5), "RULE-001"),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.Single(groups[0].Occurrences);
    }

    // ---------- Two detectors/rules at one location → both provenance entries preserved ----------

    [Fact]
    public void Two_detectors_at_one_location_preserve_both_provenance_entries()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", L(1, 1, 0, 5), "RULE-001", "DET-A"),
            MakeCandidate("secret-abc", L(1, 1, 0, 5), "RULE-002", "DET-B"),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.Single(groups[0].Occurrences);
        Assert.Equal(2, groups[0].Occurrences[0].Provenance.Count);
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.DetectorId.Value == "DET-A");
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.DetectorId.Value == "DET-B");
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.RuleId.Value == "RULE-001");
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.RuleId.Value == "RULE-002");
    }

    // ---------- Severity takes policy maximum ----------

    [Fact]
    public void Severity_is_policy_maximum_across_occurrences()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", severity: Severity.Low, confidence: DetectionConfidence.High),
            MakeCandidate("secret-abc", severity: Severity.Critical, confidence: DetectionConfidence.High),
            MakeCandidate("secret-abc", severity: Severity.Medium, confidence: DetectionConfidence.High),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.Equal(Severity.Critical, groups[0].Severity);
    }

    // ---------- Confidence is independent ----------

    [Fact]
    public void Confidence_remains_independent_per_provenance()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", confidence: DetectionConfidence.Low),
            MakeCandidate("secret-abc", confidence: DetectionConfidence.High),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.Single(groups[0].Occurrences); // same location
        Assert.Equal(2, groups[0].Occurrences[0].Provenance.Count);
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.Confidence == DetectionConfidence.Low);
        Assert.Contains(groups[0].Occurrences[0].Provenance, p => p.Confidence == DetectionConfidence.High);
    }

    // ---------- Approved-example disposition visible ----------

    [Fact]
    public void Requires_semantic_review_flag_is_preserved_in_provenance()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", requiresSemantic: true),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Single(groups);
        Assert.True(groups[0].Occurrences[0].Provenance[0].RequiresSemanticReview);
    }

    // ---------- ToDiagnosticRecord does not expose raw value ----------

    [Fact]
    public void ToDiagnosticRecord_exposes_ids_category_severity_count_only()
    {
        var candidates = new[]
        {
            MakeCandidate("secret-abc", L(1, 1, 0, 5), "RULE-001", "DET-A"),
            MakeCandidate("secret-abc", L(2, 1, 10, 5), "RULE-001", "DET-A"),
        };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var groups = merger.Merge(ScanId, JobId, candidates.AsReadOnly(), "file-sha256", "file.txt");

        var record = groups[0].ToDiagnosticRecord();
        Assert.Equal(groups[0].Id, record.GroupId);
        Assert.Equal(groups[0].FindingKind, record.Category);
        Assert.Equal(groups[0].Severity, record.Severity);
        Assert.Equal(2, record.OccurrenceCount);

        // Verify no raw value leakage
        var json = System.Text.Json.JsonSerializer.Serialize(record);
        Assert.DoesNotContain("secret-abc", json);
    }

    // ---------- FindingGroupId / FindingOccurrenceId are deterministic UUIDv5 ----------

    [Fact]
    public void Group_id_is_deterministic_for_same_fingerprint()
    {
        var candidates1 = new[] { MakeCandidate("hello") };
        var candidates2 = new[] { MakeCandidate("hello") };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var g1 = merger.Merge(ScanId, JobId, candidates1.AsReadOnly(), "file-sha256", "file.txt");
        var g2 = merger.Merge(ScanId, JobId, candidates2.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Equal(g1[0].Id, g2[0].Id);
    }

    [Fact]
    public void Occurrence_id_is_deterministic_for_same_key()
    {
        var candidates1 = new[] { MakeCandidate("hello", L(1, 1, 0, 5), "RULE-001", "DET-A") };
        var candidates2 = new[] { MakeCandidate("hello", L(1, 1, 0, 5), "RULE-001", "DET-A") };

        var merger = new CandidateMerger(new EphemeralValueFingerprintStub());
        var g1 = merger.Merge(ScanId, JobId, candidates1.AsReadOnly(), "file-sha256", "file.txt");
        var g2 = merger.Merge(ScanId, JobId, candidates2.AsReadOnly(), "file-sha256", "file.txt");

        Assert.Equal(g1[0].Occurrences[0].Id, g2[0].Occurrences[0].Id);
    }

    // ---------- Stub fingerprint for deterministic tests ----------

    private sealed class EphemeralValueFingerprintStub : IValueFingerprintService
    {
        public ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(normalizedValue.ToString());
            byte[] hash = SHA256.HashData(utf8);
            return new ValueFingerprint(Convert.ToHexStringLower(hash));
        }
    }
}
