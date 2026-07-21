namespace SecurityReview.Application.Reporting;

/// <summary>
/// Exports a validated six-sheet XLSX report for a scan. The entire
/// export is atomic: a temp file is written, verified, and then moved
/// to the target path via <c>File.Move</c>. If the target already exists,
/// the operation returns <c>target_exists</c> without overwriting.
/// </summary>
public interface IXlsxReportExporter
{
    /// <summary>
    /// Export the full six-sheet report to <paramref name="command.TargetPath"/>.
    /// </summary>
    Task<ReportExportResult> ExportAsync(
        ExportXlsxCommand command,
        IReportDataReader reader,
        CancellationToken ct = default);
}
