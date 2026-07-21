using SecurityReview.Domain;

namespace SecurityReview.Application.Reporting;

/// <summary>
/// Result of an XLSX export operation. Status codes are the single source of
/// truth for the export outcome; callers must branch on <see cref="Status"/>
/// rather than inspecting other fields.
/// </summary>
public sealed record ReportExportResult(
    ScanId ScanId,
    string Status,
    string? TargetSha256,
    long ExportedAtUnixSeconds,
    IReadOnlyDictionary<string, int> RowCounts)
{
    public static ReportExportResult Exported(
        ScanId scanId,
        string sha256,
        long unixSeconds,
        IReadOnlyDictionary<string, int> counts) =>
        new(scanId, "exported", sha256, unixSeconds, counts);

    public static ReportExportResult TargetExists(ScanId scanId) =>
        new(scanId, "target_exists", null, DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            new Dictionary<string, int>());

    public static ReportExportResult RowLimitExceeded(ScanId scanId, string sheetName, int count) =>
        new(scanId, "xlsx_row_limit_exceeded", null, DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            new Dictionary<string, int> { [sheetName] = count });

    public static ReportExportResult CellLimitExceeded(ScanId scanId) =>
        new(scanId, "xlsx_cell_limit_exceeded", null, DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            new Dictionary<string, int>());
}
