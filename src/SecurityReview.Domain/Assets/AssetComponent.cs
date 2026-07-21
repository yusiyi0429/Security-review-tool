namespace SecurityReview.Domain.Assets;

// A scan-root-relative component mapping. Paths are normalized to forward
// slashes and must never escape the selected scan root: no absolute paths,
// no drive qualifiers, no dot segments, no NUL bytes.
public sealed record AssetComponent(string RelativePath, AssetTypeId AssetType)
{
    public static AssetComponent Create(string path, AssetTypeId type)
    {
        string normalized = path.Replace('\\', '/').Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            normalized = ".";
        }

        if (normalized == ".")
        {
            return new(normalized, type);
        }

        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        bool looksAbsolute = Path.IsPathRooted(path)
            || normalized[0] == '/'
            || normalized.StartsWith("//", StringComparison.Ordinal)
            || (normalized.Length >= 2 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':');
        if (looksAbsolute || segments.Any(x => x is "." or "..") || normalized.Contains('\0'))
        {
            throw new ArgumentException("Component path must remain below the scan root.", nameof(path));
        }

        return new(normalized, type);
    }
}
