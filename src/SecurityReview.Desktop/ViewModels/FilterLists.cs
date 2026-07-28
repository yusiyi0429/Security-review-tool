using SecurityReview.Domain.Findings;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// Simple boolean-to-visibility converter for WPF bindings.
/// </summary>
public static class BooleanConverters
{
    public static readonly System.Windows.Controls.BooleanToVisibilityConverter BoolToVis = new();
}

/// <summary>
/// Static filter option lists for ComboBox binding in ScanResultsView.
/// </summary>
public static class FilterLists
{
    public static readonly FindingKindFilterOption[] FindingKindOptions =
    [
        new(null, "全部类别"),
        new(FindingKind.SensitiveContent, "敏感内容"),
        new(FindingKind.AssetCompliance, "资产合规"),
    ];

    public static readonly SeverityFilterOption[] SeverityOptions =
    [
        new(null, "全部级别"),
        new(Severity.Critical, "严重"),
        new(Severity.High, "高"),
        new(Severity.Medium, "中"),
        new(Severity.Low, "低"),
        new(Severity.Info, "信息"),
    ];

    public static readonly DetectionConfidence[] Confidences =
        Enum.GetValues<DetectionConfidence>();

    public static readonly Domain.Reviews.ReviewStatus[] ReviewStatuses =
        Enum.GetValues<Domain.Reviews.ReviewStatus>();

    public static readonly Domain.Reviews.DifferenceStatus[] DifferenceStatuses =
        Enum.GetValues<Domain.Reviews.DifferenceStatus>();
}

public sealed record FindingKindFilterOption(
    FindingKind? Value,
    string Display);

public sealed record SeverityFilterOption(
    Severity? Value,
    string Display);
