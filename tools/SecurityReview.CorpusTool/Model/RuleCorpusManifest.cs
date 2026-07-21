using System.Text.Json.Serialization;

namespace SecurityReview.CorpusTool.Model;

/// <summary>
/// Machine-readable manifest linking synthetic rule-corpus fixtures
/// to expected detector findings, locations, provenance, and coverage.
/// </summary>
public sealed record RuleCorpusManifest
{
    /// <summary>Manifest schema version.</summary>
    public required string Version { get; init; }

    /// <summary>SHA-256 of the rule pack ZIP this manifest was recorded against.</summary>
    public required string RulePackSha256 { get; init; }

    /// <summary>All rule corpus test cases.</summary>
    public required IReadOnlyList<RuleCorpusCase> Cases { get; init; }
}

/// <summary>A single rule corpus test case with expected detection behaviour.</summary>
public sealed record RuleCorpusCase
{
    /// <summary>Unique case identifier (e.g. "dictionary/api_key_positive").</summary>
    public required string CaseId { get; init; }

    /// <summary>Relative fixture path from the corpus root.</summary>
    public required string FixturePath { get; init; }

    /// <summary>Lowercase hex-encoded SHA-256 of the fixture file.</summary>
    public required string Sha256 { get; init; }

    /// <summary>Declared format identifier (e.g. "text", "json").</summary>
    public required string Format { get; init; }

    /// <summary>Asset types this case is expected to match against.</summary>
    public required IReadOnlyList<string> AssetTypeIds { get; init; }

    /// <summary>Synthetic input generator description.</summary>
    public required string Generator { get; init; }

    /// <summary>Seed value for deterministic synthetic generation.</summary>
    public required string Seed { get; init; }

    /// <summary>Expected detection findings with exact location and provenance.</summary>
    public required IReadOnlyList<ExpectedRuleFinding> ExpectedFindings { get; init; }

    /// <summary>Rule IDs that must NOT produce any finding.</summary>
    public required IReadOnlyList<string> ExpectedAbsenceRuleIds { get; init; }

    /// <summary>Minimum total expected candidate occurrences.</summary>
    public required int MinOccurrenceCount { get; init; }

    /// <summary>Maximum total expected candidate occurrences.</summary>
    public required int MaxOccurrenceCount { get; init; }

    /// <summary>Maximum allowed processing duration in milliseconds.</summary>
    public required int MaxDurationMs { get; init; }

    /// <summary>Maximum allowed worker memory in MB.</summary>
    public required int MaxMemoryMb { get; init; }

    /// <summary>
    /// Disposition: "approved-example" (known positive), "near-miss" (should NOT match),
    /// "negative" (no findings expected), "cross-chunk" (spans chunks).
    /// </summary>
    public required string Disposition { get; init; }
}

/// <summary>Expected detection finding with location and provenance.</summary>
public sealed record ExpectedRuleFinding
{
    /// <summary>Expected RuleId (e.g. "RULE-SENS-API-KEY").</summary>
    public required string RuleId { get; init; }

    /// <summary>Expected DetectorId (e.g. "DET-REGEX-API-KEY").</summary>
    public required string DetectorId { get; init; }

    /// <summary>Expected CategoryId (e.g. "SENS-001").</summary>
    public required string CategoryId { get; init; }

    /// <summary>Expected severity ("Critical", "High", "Medium", "Low", "Info").</summary>
    public required string Severity { get; init; }

    /// <summary>Expected detection confidence ("High", "Medium", "Low").</summary>
    public required string Confidence { get; init; }

    /// <summary>Substring or pattern expected in the candidate value.</summary>
    public string? ValuePattern { get; init; }

    /// <summary>Expected source location for positive cases.</summary>
    public required ExpectedFindingLocation Location { get; init; }

    /// <summary>Expected provenance entries.</summary>
    public IReadOnlyList<ExpectedFindingProvenance> Provenance { get; init; } = Array.Empty<ExpectedFindingProvenance>();
}

/// <summary>Expected source location for a finding.</summary>
public sealed record ExpectedFindingLocation
{
    /// <summary>Type of source locator: TextLocator, JsonLocator, CellLocator, etc.</summary>
    public required string LocatorType { get; init; }

    /// <summary>Line number (1-based) for TextLocator.</summary>
    public int? Line { get; init; }

    /// <summary>Column number (1-based) for TextLocator.</summary>
    public int? Column { get; init; }

    /// <summary>Byte start offset.</summary>
    public long? ByteStart { get; init; }

    /// <summary>Byte length.</summary>
    public long? ByteLength { get; init; }
}

/// <summary>Expected provenance entry linking a detector and rule.</summary>
public sealed record ExpectedFindingProvenance
{
    /// <summary>DetectorId in the provenance chain.</summary>
    public required string DetectorId { get; init; }

    /// <summary>RuleId in the provenance chain.</summary>
    public required string RuleId { get; init; }
}

/// <summary>Summary result of a verify-rule-corpus run.</summary>
public sealed record RuleCorpusResult
{
    /// <summary>Total number of cases processed.</summary>
    public required int TotalCases { get; init; }

    /// <summary>Number of cases that passed.</summary>
    public required int Passed { get; init; }

    /// <summary>Number of cases that failed.</summary>
    public required int Failed { get; init; }

    /// <summary>Number of cases skipped (e.g. missing fixture).</summary>
    public required int Skipped { get; init; }

    /// <summary>Per-case results.</summary>
    public required IReadOnlyList<CaseResult> Cases { get; init; }
}

/// <summary>Source-generated JSON serialization context for rule corpus manifest types.</summary>
[JsonSerializable(typeof(RuleCorpusManifest))]
[JsonSerializable(typeof(RuleCorpusResult))]
[JsonSerializable(typeof(RuleCorpusCase))]
[JsonSerializable(typeof(ExpectedRuleFinding))]
[JsonSerializable(typeof(ExpectedFindingLocation))]
[JsonSerializable(typeof(ExpectedFindingProvenance))]
[JsonSerializable(typeof(CaseResult))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public sealed partial class RuleCorpusJsonContext : JsonSerializerContext
{
}
