using System.Diagnostics.CodeAnalysis;

namespace SecurityReview.Application.Updates;

/// <summary>
/// Pure helpers for comparing release tags against the running version.
/// Accepted tag form is <c>v1.2.3</c> (the <c>v</c> prefix is optional and
/// case-insensitive) with exactly three numeric components. Prerelease tags
/// (anything containing <c>-</c>, e.g. <c>v1.4.0-rc.1</c>) and any other
/// malformed tag are rejected, so callers treat them as "cannot determine"
/// and never offer an update from them.
/// </summary>
public static class UpdateVersionComparer
{
    /// <summary>
    /// Parses a stable release tag into a three-component
    /// <see cref="Version"/>. Returns <c>false</c> for <c>null</c>/empty
    /// input, prerelease tags, and anything that is not exactly
    /// <c>major.minor.patch</c> with non-negative integer components.
    /// </summary>
    public static bool TryParseTag(string? tag, [NotNullWhen(true)] out Version? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(tag))
        {
            return false;
        }

        var candidate = tag.Trim();
        if (candidate.StartsWith('v') || candidate.StartsWith('V'))
        {
            candidate = candidate[1..];
        }

        // Prerelease/build-metadata tags are never considered stable updates.
        if (candidate.Contains('-', StringComparison.Ordinal))
        {
            return false;
        }

        var parts = candidate.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        Span<int> components = stackalloc int[3];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], out components[i]) || components[i] < 0)
            {
                return false;
            }
        }

        version = new Version(components[0], components[1], components[2]);
        return true;
    }

    /// <summary>
    /// Returns <c>true</c> only when both tags parse as stable versions and
    /// <paramref name="latestTag"/> is strictly newer than
    /// <paramref name="currentTag"/>. Any unparsable input (including
    /// prerelease tags) yields <c>false</c>, i.e. "no update / cannot
    /// determine".
    /// </summary>
    public static bool IsNewer(string? currentTag, string? latestTag)
    {
        if (!TryParseTag(currentTag, out var current) || !TryParseTag(latestTag, out var latest))
        {
            return false;
        }

        return latest.CompareTo(current) > 0;
    }
}
