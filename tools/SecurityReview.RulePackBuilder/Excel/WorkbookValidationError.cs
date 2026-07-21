namespace SecurityReview.RulePackBuilder.Excel;

/// <summary>
/// Describes a validation error found when reading a rule workbook.
/// Cell values and entity data must never appear in the message.
/// </summary>
public sealed record WorkbookValidationError(
    string Code,
    string Sheet,
    int Row,
    string Column,
    string Message)
{
    public const string MissingSheet = "MissingSheet";
    public const string ExtraSheet = "ExtraSheet";
    public const string MissingHeader = "MissingHeader";
    public const string ExtraHeader = "ExtraHeader";
    public const string DuplicateHeader = "DuplicateHeader";
    public const string FormulaCell = "FormulaCell";
    public const string ExternalLink = "ExternalLink";
    public const string MacroPart = "MacroPart";
    public const string InvalidJson = "InvalidJson";
    public const string DuplicateId = "DuplicateId";
    public const string DanglingReference = "DanglingReference";
    public const string VersionRollback = "VersionRollback";
    public const string UnsafeRegex = "UnsafeRegex";
    public const string InvalidCellValue = "InvalidCellValue";
    public const string RowLimitExceeded = "RowLimitExceeded";
    public const string CellTooLong = "CellTooLong";
}
