using SecurityReview.Domain;

namespace SecurityReview.Application.Reporting;

/// <summary>
/// Command to export a six-sheet XLSX report for a completed scan.
/// Target path must end with <c>.xlsx</c> and the caller must assert
/// <see cref="ContainsCompleteSensitiveValues"/> to acknowledge that
/// raw finding values will appear in the output.
/// </summary>
public sealed record ExportXlsxCommand(
    ScanId ScanId,
    string TargetPath,
    bool ContainsCompleteSensitiveValues);
