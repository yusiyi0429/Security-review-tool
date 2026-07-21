using System.Text.Json.Serialization;

namespace SecurityReview.CorpusTool.Model;

/// <summary>
/// Machine-readable acceptance manifest linking every REQ/AC/SRS-F/VT
/// to executable scenarios with expected scan, finding, locator, gap,
/// review, diff, cache, report, network, and diagnostic assertions.
/// </summary>
public sealed record AcceptanceManifest
{
    /// <summary>Manifest schema version.</summary>
    public required string Version { get; init; }

    /// <summary>All acceptance test scenarios.</summary>
    public required IReadOnlyList<AcceptanceScenario> Scenarios { get; init; }
}

/// <summary>A single acceptance test scenario with all expected assertions.</summary>
public sealed record AcceptanceScenario
{
    /// <summary>Unique scenario identifier (e.g. ACC-001).</summary>
    public required string Id { get; init; }

    /// <summary>Human-readable scenario description.</summary>
    public required string Description { get; init; }

    /// <summary>Linked BRD requirements (REQ-001..019).</summary>
    public required IReadOnlyList<string> LinkedReqs { get; init; }

    /// <summary>Linked acceptance criteria (AC-001..060).</summary>
    public required IReadOnlyList<string> LinkedAcs { get; init; }

    /// <summary>Linked SRS functional requirements (SRS-F-001..019).</summary>
    public required IReadOnlyList<string> LinkedSrsFs { get; init; }

    /// <summary>Linked verification test cases (VT-001..035).</summary>
    public required IReadOnlyList<string> LinkedVts { get; init; }

    /// <summary>Required OS capability: any, windows-sandbox, or windows-gui.</summary>
    public required string RequiredOsCapability { get; init; }

    /// <summary>Maximum allowed processing duration in milliseconds.</summary>
    public required int MaxDurationMs { get; init; }

    /// <summary>Maximum allowed worker memory in MB.</summary>
    public required int MaxMemoryMb { get; init; }

    /// <summary>Fields to normalize during comparison: uuid, timestamp, tempPath.</summary>
    public IReadOnlyList<string>? VariableFields { get; init; }

    /// <summary>Description of synthetic assets to generate for this scenario.</summary>
    public SyntheticInputDescription? SyntheticInput { get; init; }

    /// <summary>Expected scan outcome assertions.</summary>
    public ExpectedScanAssertions? ExpectedScan { get; init; }

    /// <summary>Expected bounded conclusion assertions.</summary>
    public ExpectedConclusionAssertions? ExpectedConclusion { get; init; }

    /// <summary>Expected finding patterns (value patterns, not exact UUID-dependent values).</summary>
    public IReadOnlyList<ExpectedAcceptanceFinding>? ExpectedFindings { get; init; }

    /// <summary>Expected locator patterns for findings.</summary>
    public IReadOnlyList<ExpectedLocator>? ExpectedLocators { get; init; }

    /// <summary>Expected coverage gaps.</summary>
    public IReadOnlyList<ExpectedAcceptanceGap>? ExpectedGaps { get; init; }

    /// <summary>Expected review behaviour.</summary>
    public ExpectedReviewAssertions? ExpectedReviews { get; init; }

    /// <summary>Expected diff behaviour on rescan.</summary>
    public ExpectedDiffAssertions? ExpectedDiff { get; init; }

    /// <summary>Expected cache behaviour.</summary>
    public ExpectedCacheAssertions? ExpectedCache { get; init; }

    /// <summary>Expected XLSX report assertions.</summary>
    public ExpectedReportAssertions? ExpectedReport { get; init; }

    /// <summary>Expected network behaviour assertions.</summary>
    public ExpectedNetworkAssertions? ExpectedNetwork { get; init; }

    /// <summary>Expected diagnostic assertions.</summary>
    public ExpectedDiagnosticAssertions? ExpectedDiagnostic { get; init; }
}

/// <summary>Description of synthetic assets to generate for an acceptance scenario.</summary>
public sealed record SyntheticInputDescription
{
    /// <summary>Human-readable description of the synthetic input.</summary>
    public string? Description { get; init; }

    /// <summary>Number of files to generate.</summary>
    public int? FileCount { get; init; }

    /// <summary>Whether to generate a secret candidate file.</summary>
    public bool? GenerateSecretCandidate { get; init; }

    /// <summary>Whether to generate a corrupt file.</summary>
    public bool? GenerateCorruptFile { get; init; }

    /// <summary>Whether to generate an encrypted file.</summary>
    public bool? GenerateEncryptedFile { get; init; }

    /// <summary>Whether to generate an archive.</summary>
    public bool? GenerateArchive { get; init; }

    /// <summary>Whether to generate an OCI layout.</summary>
    public bool? GenerateOciLayout { get; init; }

    /// <summary>Whether to generate an Office file.</summary>
    public bool? GenerateOfficeFile { get; init; }

    /// <summary>Whether to generate a PDF file.</summary>
    public bool? GeneratePdfFile { get; init; }

    /// <summary>Whether to generate a Python file.</summary>
    public bool? GeneratePythonFile { get; init; }

    /// <summary>Whether to generate a JAR file.</summary>
    public bool? GenerateJarFile { get; init; }

    /// <summary>Whether to generate a binary file.</summary>
    public bool? GenerateBinaryFile { get; init; }

    /// <summary>Whether to generate multi-encoding files.</summary>
    public bool? GenerateMultiEncodingFiles { get; init; }

    /// <summary>Whether to generate a rule pack.</summary>
    public bool? GenerateRulePack { get; init; }

    /// <summary>Whether to use a mock LLM backend.</summary>
    public bool? UseMockLlm { get; init; }

    /// <summary>Mock LLM outcome: confirmed, rejected, unresolved, injection-detected, timeout, or unavailable.</summary>
    public string? MockLlmOutcome { get; init; }

    /// <summary>Hint for total bytes to generate.</summary>
    public int? TotalBytesHint { get; init; }
}

/// <summary>Expected scan outcome assertions.</summary>
public sealed record ExpectedScanAssertions
{
    /// <summary>Expected terminal scan status: Completed, Partial, Failed, or Cancelled.</summary>
    public string? Status { get; init; }

    /// <summary>Minimum expected finding count.</summary>
    public int? MinFindings { get; init; }

    /// <summary>Maximum expected finding count.</summary>
    public int? MaxFindings { get; init; }

    /// <summary>Minimum expected file count.</summary>
    public int? MinFiles { get; init; }

    /// <summary>Maximum expected file count.</summary>
    public int? MaxFiles { get; init; }

    /// <summary>Minimum expected chunk count.</summary>
    public int? MinChunks { get; init; }

    /// <summary>Minimum expected gap count.</summary>
    public int? MinGaps { get; init; }

    /// <summary>Maximum expected gap count.</summary>
    public int? MaxGaps { get; init; }
}

/// <summary>Expected bounded conclusion assertions.</summary>
public sealed record ExpectedConclusionAssertions
{
    /// <summary>Whether the conclusion must be bounded.</summary>
    public bool? IsBounded { get; init; }

    /// <summary>Whether the conclusion must not be absolute.</summary>
    public bool? IsNotAbsolute { get; init; }

    /// <summary>Expected partial reason text.</summary>
    public string? PartialReason { get; init; }
}

/// <summary>Expected finding pattern (value patterns, not exact UUID-dependent values).</summary>
public sealed record ExpectedAcceptanceFinding
{
    /// <summary>Substring or regex pattern expected in finding value.</summary>
    public required string ValuePattern { get; init; }

    /// <summary>Expected severity: Critical, High, Medium, Low, or Info.</summary>
    public string? Severity { get; init; }

    /// <summary>Expected kind: SensitiveContent or AssetCompliance.</summary>
    public string? Kind { get; init; }

    /// <summary>Expected category identifier.</summary>
    public string? CategoryId { get; init; }

    /// <summary>Whether the finding requires semantic review.</summary>
    public bool? RequiresSemanticReview { get; init; }
}

/// <summary>Expected locator pattern for a finding.</summary>
public sealed record ExpectedLocator
{
    /// <summary>Locator type: TextLocator, JsonLocator, CellLocator, ByteLocator, or NestedLocator.</summary>
    public required string LocatorType { get; init; }

    /// <summary>Expected line number (1-based).</summary>
    public int? Line { get; init; }

    /// <summary>Expected column number (1-based).</summary>
    public int? Column { get; init; }

    /// <summary>Expected byte start offset.</summary>
    public int? ByteStart { get; init; }

    /// <summary>Expected byte length.</summary>
    public int? ByteLength { get; init; }

    /// <summary>Expected virtual path within the scan tree.</summary>
    public string? VirtualPath { get; init; }
}

/// <summary>Expected coverage gap assertion.</summary>
public sealed record ExpectedAcceptanceGap
{
    /// <summary>Gap reason: UnsupportedFormat, AccessDenied, Encrypted, DecodeUnreliable, Corrupt, etc.</summary>
    public required string Reason { get; init; }

    /// <summary>Detail code identifying the specific gap condition.</summary>
    public string? DetailCode { get; init; }

    /// <summary>Virtual path where the gap was raised (null for file-level gaps).</summary>
    public string? VirtualPath { get; init; }
}

/// <summary>Expected review behaviour assertions.</summary>
public sealed record ExpectedReviewAssertions
{
    /// <summary>Whether findings can be marked as reviewed.</summary>
    public bool? CanMarkReviewed { get; init; }

    /// <summary>Whether exceptions can be added.</summary>
    public bool? CanAddException { get; init; }

    /// <summary>Whether the exception is bound to a specific version.</summary>
    public bool? ExceptionBoundToVersion { get; init; }
}

/// <summary>Expected diff behaviour assertions on rescan.</summary>
public sealed record ExpectedDiffAssertions
{
    /// <summary>Whether new findings are detected on rescan.</summary>
    public bool? DetectsNewFindings { get; init; }

    /// <summary>Whether disappeared findings are detected on rescan.</summary>
    public bool? DetectsDisappearedFindings { get; init; }

    /// <summary>Whether persistent findings are detected on rescan.</summary>
    public bool? DetectsPersistentFindings { get; init; }
}

/// <summary>Expected cache behaviour assertions.</summary>
public sealed record ExpectedCacheAssertions
{
    /// <summary>Whether the parse cache is reused when inputs are unchanged.</summary>
    public bool? ReusesParseCacheWhenUnchanged { get; init; }

    /// <summary>Whether the cache is invalidated on rule changes.</summary>
    public bool? InvalidatesCacheOnRuleChange { get; init; }

    /// <summary>Whether the cache is invalidated on file changes.</summary>
    public bool? InvalidatesCacheOnFileChange { get; init; }
}

/// <summary>Expected XLSX report assertions.</summary>
public sealed record ExpectedReportAssertions
{
    /// <summary>Expected number of sheets in the report.</summary>
    public int? SheetCount { get; init; }

    /// <summary>Whether the report has a summary sheet.</summary>
    public bool? HasSummarySheet { get; init; }

    /// <summary>Whether the report has a findings sheet.</summary>
    public bool? HasFindingsSheet { get; init; }

    /// <summary>Whether the report has a gaps sheet.</summary>
    public bool? HasGapsSheet { get; init; }

    /// <summary>Whether the report has a reviews sheet.</summary>
    public bool? HasReviewsSheet { get; init; }

    /// <summary>Whether the report has an assets sheet.</summary>
    public bool? HasAssetsSheet { get; init; }

    /// <summary>Whether the report has a versions sheet.</summary>
    public bool? HasVersionsSheet { get; init; }

    /// <summary>Whether the report is free of formula injection.</summary>
    public bool? NoFormulaInjection { get; init; }

    /// <summary>Whether the report is free of external links.</summary>
    public bool? NoExternalLinks { get; init; }
}

/// <summary>Expected network behaviour assertions.</summary>
public sealed record ExpectedNetworkAssertions
{
    /// <summary>Whether no external telemetry is sent.</summary>
    public bool? NoExternalTelemetry { get; init; }

    /// <summary>Whether only the LLM endpoint is contacted.</summary>
    public bool? OnlyLlmEndpointContacted { get; init; }

    /// <summary>Whether no sensitive data is present in network requests.</summary>
    public bool? NoSensitiveDataInRequests { get; init; }
}

/// <summary>Expected diagnostic assertions.</summary>
public sealed record ExpectedDiagnosticAssertions
{
    /// <summary>Whether no asset content appears in logs.</summary>
    public bool? NoAssetContentInLogs { get; init; }

    /// <summary>Whether no sensitive values appear in logs.</summary>
    public bool? NoSensitiveValuesInLogs { get; init; }

    /// <summary>Whether no LLM request body appears in logs.</summary>
    public bool? NoLlmRequestBodyInLogs { get; init; }
}

/// <summary>Summary result of a verify-acceptance-manifest run.</summary>
public sealed record AcceptanceResult
{
    /// <summary>Total number of cases processed.</summary>
    public required int TotalCases { get; init; }

    /// <summary>Number of cases that passed.</summary>
    public required int Passed { get; init; }

    /// <summary>Number of cases that failed.</summary>
    public required int Failed { get; init; }

    /// <summary>Number of cases skipped.</summary>
    public required int Skipped { get; init; }

    /// <summary>Per-case results.</summary>
    public required IReadOnlyList<AcceptanceCaseResult> Cases { get; init; }
}

/// <summary>Result for a single acceptance case.</summary>
public sealed record AcceptanceCaseResult
{
    /// <summary>Case identifier from the manifest.</summary>
    public required string CaseId { get; init; }

    /// <summary>Outcome: "pass", "fail", or "skip".</summary>
    public required string Result { get; init; }

    /// <summary>Actual duration in milliseconds.</summary>
    public long DurationMs { get; init; }

    /// <summary>Human-readable detail when result is not "pass".</summary>
    public string? Detail { get; init; }
}

/// <summary>Source-generated JSON serialization context for acceptance manifest types.</summary>
[JsonSerializable(typeof(AcceptanceManifest))]
[JsonSerializable(typeof(AcceptanceResult))]
[JsonSerializable(typeof(AcceptanceScenario))]
[JsonSerializable(typeof(SyntheticInputDescription))]
[JsonSerializable(typeof(ExpectedScanAssertions))]
[JsonSerializable(typeof(ExpectedConclusionAssertions))]
[JsonSerializable(typeof(ExpectedAcceptanceFinding))]
[JsonSerializable(typeof(ExpectedLocator))]
[JsonSerializable(typeof(ExpectedAcceptanceGap))]
[JsonSerializable(typeof(ExpectedReviewAssertions))]
[JsonSerializable(typeof(ExpectedDiffAssertions))]
[JsonSerializable(typeof(ExpectedCacheAssertions))]
[JsonSerializable(typeof(ExpectedReportAssertions))]
[JsonSerializable(typeof(ExpectedNetworkAssertions))]
[JsonSerializable(typeof(ExpectedDiagnosticAssertions))]
[JsonSerializable(typeof(AcceptanceCaseResult))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public sealed partial class AcceptanceJsonContext : JsonSerializerContext
{
}
