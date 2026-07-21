namespace SecurityReview.Application.Rules;

/// <summary>
/// Command to import and activate a rule pack ZIP.
/// </summary>
public sealed record ImportRulePackCommand
{
    public byte[] ZipBytes { get; init; } = Array.Empty<byte>();
    public bool AllowDowngrade { get; init; }
    public string? LocalSupplementJson { get; init; }
}
