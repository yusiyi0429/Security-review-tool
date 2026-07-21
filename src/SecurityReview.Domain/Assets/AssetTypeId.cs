namespace SecurityReview.Domain.Assets;

[System.Text.Json.Serialization.JsonConverter(typeof(SecurityReview.Domain.AssetTypeIdJsonConverter))]
public readonly record struct AssetTypeId
{
    private static readonly HashSet<string> Allowed =
        Enumerable.Range(1, 11).Select(i => $"ASSET-{i:000}").ToHashSet(StringComparer.Ordinal);

    public string Value { get; }

    private AssetTypeId(string value) => Value = value;

    public static AssetTypeId Parse(string value) => Allowed.Contains(value)
        ? new(value)
        : throw new ArgumentException("Unknown asset type.", nameof(value));
}
