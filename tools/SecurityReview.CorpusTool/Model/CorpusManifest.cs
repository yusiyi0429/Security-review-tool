using System.Text.Json.Serialization;

namespace SecurityReview.CorpusTool.Model;

/// <summary>
/// Machine-readable corpus manifest linking every adversarial fixture
/// to expected parser events, gaps, and coverage.
/// </summary>
public sealed record CorpusManifest
{
    /// <summary>Manifest schema version.</summary>
    public required string Version { get; init; }

    /// <summary>All corpus cases.</summary>
    public required IReadOnlyList<CorpusCase> Cases { get; init; }
}

/// <summary>A single corpus test case with expected parser behaviour.</summary>
public sealed record CorpusCase
{
    /// <summary>Unique case identifier (e.g. "archives/traversal_zip").</summary>
    public required string CaseId { get; init; }

    /// <summary>Relative fixture path from the corpus root.</summary>
    public required string FixturePath { get; init; }

    /// <summary>Lowercase hex-encoded SHA-256 of the fixture file.</summary>
    public required string Sha256 { get; init; }

    /// <summary>Declared format identifier (e.g. "zip", "pdf", "text").</summary>
    public required string Format { get; init; }

    /// <summary>The ParserId of the parser expected to handle this case.</summary>
    public required string ExpectedParser { get; init; }

    /// <summary>Parser version string.</summary>
    public required string ExpectedParserVersion { get; init; }

    /// <summary>Expected chunks with HMAC canary labels and locator fields.</summary>
    public required IReadOnlyList<ExpectedChunk> ExpectedChunks { get; init; }

    /// <summary>Expected coverage gaps.</summary>
    public required IReadOnlyList<ExpectedGap> ExpectedGaps { get; init; }

    /// <summary>Maximum allowed processing duration in milliseconds.</summary>
    public required int MaxDurationMs { get; init; }

    /// <summary>Maximum allowed worker memory in MB.</summary>
    public required int MaxMemoryMb { get; init; }

    /// <summary>Expected coverage status: Covered, Partial, or NotCovered.</summary>
    public required string Coverage { get; init; }
}

/// <summary>Expected chunk identified by HMAC canary label and locator.</summary>
public sealed record ExpectedChunk
{
    /// <summary>HMAC canary: SHA-256 hex digest of the chunk's Text content.</summary>
    public required string Label { get; init; }

    /// <summary>Byte offset of this chunk in the source file.</summary>
    public required long SourceStart { get; init; }

    /// <summary>Byte length of this chunk in the source file.</summary>
    public required long SourceLength { get; init; }

    /// <summary>Virtual path within the scan tree.</summary>
    public required string VirtualPath { get; init; }

    /// <summary>Format identifier for this chunk.</summary>
    public required string FormatId { get; init; }

    /// <summary>Content kind: Text, StructuredData, Metadata, or Binary.</summary>
    public required string ContentKind { get; init; }

    /// <summary>Optional text encoding name.</summary>
    public string? Encoding { get; init; }
}

/// <summary>Expected coverage gap.</summary>
public sealed record ExpectedGap
{
    /// <summary>GapReason enum member name (e.g. "Encrypted", "Corrupt").</summary>
    public required string Reason { get; init; }

    /// <summary>Detail code identifying the specific gap condition.</summary>
    public required string DetailCode { get; init; }

    /// <summary>Virtual path where the gap was raised (null for file-level gaps).</summary>
    public string? VirtualPath { get; init; }
}

/// <summary>Summary result of a verify-parser-corpus run.</summary>
public sealed record CorpusResult
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

/// <summary>Result for a single corpus case.</summary>
public sealed record CaseResult
{
    /// <summary>Case identifier from the manifest.</summary>
    public required string CaseId { get; init; }

    /// <summary>Outcome: "pass", "fail", or "skip".</summary>
    public required string Result { get; init; }

    /// <summary>Actual duration in milliseconds.</summary>
    public long DurationMs { get; init; }

    /// <summary>Peak memory in MB (0 if not measured).</summary>
    public long PeakMemoryMb { get; init; }

    /// <summary>Human-readable detail when result is not "pass".</summary>
    public string? Detail { get; init; }
}

/// <summary>Source-generated JSON serialization context for manifest types.</summary>
[JsonSerializable(typeof(CorpusManifest))]
[JsonSerializable(typeof(CorpusResult))]
[JsonSerializable(typeof(CorpusCase))]
[JsonSerializable(typeof(ExpectedChunk))]
[JsonSerializable(typeof(ExpectedGap))]
[JsonSerializable(typeof(CaseResult))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public sealed partial class CorpusJsonContext : JsonSerializerContext
{
}
