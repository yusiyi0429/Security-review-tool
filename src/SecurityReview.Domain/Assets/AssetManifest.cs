namespace SecurityReview.Domain.Assets;

// Validated asset manifest: schema version 1, a non-empty asset identity and
// 1..1,000 non-overlapping component mappings below the scan root.
public sealed record AssetManifest(
    string AssetId,
    string AssetVersion,
    IReadOnlyList<AssetComponent> Components,
    ComplianceEvidence Evidence)
{
    public const int SchemaVersion = 1;
    public const int MaxComponents = 1_000;

    // Declared compliance evidence is attestation only; it can never suppress
    // content scanning, so the scan requirement is a constant, not settable state.
    public static bool RequiresContentScanning => true;

    public static AssetManifest Create(
        string assetId,
        string assetVersion,
        IReadOnlyList<AssetComponent> components,
        ComplianceEvidence evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assetId);
        ArgumentException.ThrowIfNullOrWhiteSpace(assetVersion);
        ArgumentNullException.ThrowIfNull(components);
        ArgumentNullException.ThrowIfNull(evidence);
        if (components.Count is < 1 or > MaxComponents)
        {
            throw new ArgumentException(
                "Manifest must declare 1 to 1,000 component mappings.", nameof(components));
        }

        // Component mappings must not overlap: no duplicate paths and no path
        // that contains another mapping (a mapping covers its whole subtree).
        // Comparison is ordinal-ignore-case to match Windows file semantics.
        var keys = new List<string>(components.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (AssetComponent component in components)
        {
            string key = component.RelativePath == "." ? "" : component.RelativePath;
            if (!seen.Add(key))
            {
                throw new ArgumentException(
                    "Component mappings must not overlap.", nameof(components));
            }

            keys.Add(key);
        }

        for (int i = 0; i < keys.Count; i++)
        {
            for (int j = i + 1; j < keys.Count; j++)
            {
                if (IsAncestorOf(keys[i], keys[j]) || IsAncestorOf(keys[j], keys[i]))
                {
                    throw new ArgumentException(
                        "Component mappings must not overlap.", nameof(components));
                }
            }
        }

        return new(assetId, assetVersion, components, evidence);
    }

    private static bool IsAncestorOf(string ancestor, string descendant)
    {
        if (ancestor.Length == 0)
        {
            // The root mapping "." covers every path below the scan root.
            return descendant.Length != 0;
        }

        return descendant.Length > ancestor.Length
            && descendant.StartsWith(ancestor, StringComparison.OrdinalIgnoreCase)
            && descendant[ancestor.Length] == '/';
    }
}
