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
    public static readonly FindingKind[] FindingKinds =
        Enum.GetValues<FindingKind>();

    public static readonly Severity[] Severities =
        Enum.GetValues<Severity>();

    public static readonly DetectionConfidence[] Confidences =
        Enum.GetValues<DetectionConfidence>();

    public static readonly Domain.Reviews.ReviewStatus[] ReviewStatuses =
        Enum.GetValues<Domain.Reviews.ReviewStatus>();

    public static readonly Domain.Reviews.DifferenceStatus[] DifferenceStatuses =
        Enum.GetValues<Domain.Reviews.DifferenceStatus>();
}
