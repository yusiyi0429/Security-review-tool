namespace SecurityReview.Domain.Rules;

/// <summary>
/// Import lifecycle status of a rule pack.
/// </summary>
public enum RulePackStatus
{
    Imported,
    Active,
    Superseded,
    Revoked
}
