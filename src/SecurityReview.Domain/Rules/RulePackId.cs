namespace SecurityReview.Domain.Rules;

public readonly record struct RulePackId(string Value)
{
    public override string ToString() => Value;
}
