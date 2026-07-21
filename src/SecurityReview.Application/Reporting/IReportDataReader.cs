using SecurityReview.Domain;

namespace SecurityReview.Application.Reporting;

/// <summary>
/// Reads all projection data needed to populate the six-sheet XLSX export.
/// Implementations aggregate from encrypted repositories and decrypt
/// sensitive values as needed. Every method returns the full list — the
/// exporter is responsible for row-limit enforcement.
/// </summary>
public interface IReportDataReader
{
    Task<ExportScanSummary> GetScanSummaryAsync(ScanId scanId, CancellationToken ct);

    Task<IReadOnlyList<ExportSensitiveFinding>> GetSensitiveFindingsAsync(
        ScanId scanId, CancellationToken ct);

    Task<IReadOnlyList<ExportComplianceFinding>> GetComplianceFindingsAsync(
        ScanId scanId, CancellationToken ct);

    Task<IReadOnlyList<ExportCoverageGapRow>> GetCoverageGapsAsync(
        ScanId scanId, CancellationToken ct);

    Task<IReadOnlyList<ExportFileRecordRow>> GetFileRecordsAsync(
        ScanId scanId, CancellationToken ct);

    Task<IReadOnlyList<ExportReviewRecordRow>> GetReviewRecordsAsync(
        ScanId scanId, CancellationToken ct);
}

// ---------------------------------------------------------------
// Export DTOs — one flat projection per sheet
// ---------------------------------------------------------------

/// <summary>Single-row summary of the scan (匹配 the 扫描摘要 sheet).</summary>
public sealed record ExportScanSummary(
    string ScanId,
    string TaskStatus,
    string BoundedConclusion,
    string StartTimeUtc,
    string EndTimeUtc,
    string AssetId,
    string AssetVersion,
    string InputSummary,
    string RulePackId,
    string RulePackVersion,
    string RulePackSha256,
    string LocalSupplementSha256,
    string EffectivePolicySha256,
    string ClientVersion,
    string ParserFingerprint,
    string DetectorFingerprint,
    string PromptTemplateVersion,
    string LlmModel,
    long TotalFiles,
    long TotalBytes,
    int SensitiveFindingsCount,
    int ComplianceFindingsCount,
    int UncoveredCount,
    int CacheReuseCount,
    int ContentEscapedCellCount,
    bool IsLegacyRule,
    bool IsLocalSupplement);

/// <summary>One occurrence of a sensitive-content finding (敏感内容发现).</summary>
public sealed record ExportSensitiveFinding(
    string ScanId,
    string AssetId,
    string AssetVersion,
    string FindingGroupId,
    string FindingOccurrenceId,
    string DifferenceStatus,
    string CategoryId,
    string Category,
    string Severity,
    string Confidence,
    string FullHitValue,
    string Context,
    string AssetType,
    string VirtualPath,
    string LocatorType,
    string PreciseLocation,
    string RuleId,
    string DetectorId,
    string RuleVersion,
    string LlmStatus,
    string LlmClassification,
    string LlmConfidence,
    string LlmReason,
    string HumanReviewStatus,
    string ExceptionExpiryUtc);

/// <summary>One occurrence of an asset-compliance finding (资产合规发现).</summary>
public sealed record ExportComplianceFinding(
    string ScanId,
    string AssetId,
    string AssetVersion,
    string FindingGroupId,
    string FindingOccurrenceId,
    string DifferenceStatus,
    string AssetType,
    string ComplianceRuleId,
    string Conclusion,
    string Severity,
    string EvidenceStatus,
    string EvidenceReference,
    string VirtualPath,
    string PreciseLocation,
    string HumanReviewStatus,
    string HumanReviewReason);

/// <summary>One coverage gap (未覆盖内容).</summary>
public sealed record ExportCoverageGapRow(
    string GapId,
    string Stage,
    string ReasonCode,
    string DetailCode,
    string Format,
    string VirtualPath,
    long PlannedBytes,
    long ProcessedBytes,
    string ParserId,
    string ParserVersion,
    string RecordedAtUtc);

/// <summary>One inventoried file (文件清单).</summary>
public sealed record ExportFileRecordRow(
    string FileId,
    string VirtualPath,
    string DataStream,
    string AssetType,
    string Format,
    long Size,
    string ContentSha256,
    string ParserId,
    string ParserVersion,
    string CoverageStatus,
    bool ExtensionMismatch,
    bool CacheReuse);

/// <summary>One review decision (复核记录).</summary>
public sealed record ExportReviewRecordRow(
    string DecisionId,
    string FindingGroupId,
    string FindingOccurrenceId,
    string Status,
    string Operator,
    string RecordedAtUtc,
    string Reason,
    string ExceptionBindingSummary,
    string ExceptionExpiryUtc);
