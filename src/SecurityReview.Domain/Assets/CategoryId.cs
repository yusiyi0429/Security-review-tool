namespace SecurityReview.Domain.Assets;

public readonly record struct CategoryId
{
    private static readonly HashSet<string> Allowed =
        Enumerable.Range(1, 8).Select(i => $"SENS-{i:000}").ToHashSet(StringComparer.Ordinal);

    public string Value { get; }

    private CategoryId(string value) => Value = value;

    public static CategoryId Parse(string value) => Allowed.Contains(value)
        ? new(value)
        : throw new ArgumentException("Unknown category.", nameof(value));
}
