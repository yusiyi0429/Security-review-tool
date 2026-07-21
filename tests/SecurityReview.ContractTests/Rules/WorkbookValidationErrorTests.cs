using SecurityReview.RulePackBuilder.Excel;

namespace SecurityReview.ContractTests.Rules;

public sealed class WorkbookValidationErrorTests
{
    [Fact]
    public void Error_code_constants_are_unique()
    {
        string[] codes =
        [
            WorkbookValidationError.MissingSheet,
            WorkbookValidationError.ExtraSheet,
            WorkbookValidationError.MissingHeader,
            WorkbookValidationError.ExtraHeader,
            WorkbookValidationError.DuplicateHeader,
            WorkbookValidationError.FormulaCell,
            WorkbookValidationError.ExternalLink,
            WorkbookValidationError.MacroPart,
            WorkbookValidationError.InvalidJson,
            WorkbookValidationError.DuplicateId,
            WorkbookValidationError.DanglingReference,
            WorkbookValidationError.VersionRollback,
            WorkbookValidationError.UnsafeRegex,
            WorkbookValidationError.InvalidCellValue,
            WorkbookValidationError.RowLimitExceeded,
            WorkbookValidationError.CellTooLong,
        ];

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var code in codes)
        {
            Assert.True(seen.Add(code), $"Duplicate error code: {code}");
        }
    }

    [Fact]
    public void Error_record_equality()
    {
        var a = new WorkbookValidationError("TestCode", "Sheet1", 5, "A", "Test message");
        var b = new WorkbookValidationError("TestCode", "Sheet1", 5, "A", "Test message");
        var c = new WorkbookValidationError("TestCode", "Sheet1", 6, "A", "Test message");

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Error_ToString_format()
    {
        var error = new WorkbookValidationError("MissingSheet", "敏感类别", 0, "",
            "Required sheet '敏感类别' is missing.");

        string s = error.ToString();

        Assert.Contains("MissingSheet", s, StringComparison.Ordinal);
        Assert.Contains("敏感类别", s, StringComparison.Ordinal);
        Assert.Contains("is missing", s, StringComparison.Ordinal);
    }

    [Fact]
    public void Error_code_MissingSheet_has_expected_value()
    {
        Assert.Equal("MissingSheet", WorkbookValidationError.MissingSheet);
    }

    [Fact]
    public void Error_code_FormulaCell_has_expected_value()
    {
        Assert.Equal("FormulaCell", WorkbookValidationError.FormulaCell);
    }

    [Fact]
    public void Error_code_RowLimitExceeded_has_expected_value()
    {
        Assert.Equal("RowLimitExceeded", WorkbookValidationError.RowLimitExceeded);
    }

    [Fact]
    public void Error_code_CellTooLong_has_expected_value()
    {
        Assert.Equal("CellTooLong", WorkbookValidationError.CellTooLong);
    }
}
