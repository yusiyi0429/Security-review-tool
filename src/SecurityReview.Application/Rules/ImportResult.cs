using SecurityReview.RulePack.Validation;

namespace SecurityReview.Application.Rules;

/// <summary>
/// Result of a rule pack import operation.
/// </summary>
public sealed record ImportResult
{
    public bool Success { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public ActivePointer? Active { get; init; }
    public ValidationSummary? Validation { get; init; }
}
