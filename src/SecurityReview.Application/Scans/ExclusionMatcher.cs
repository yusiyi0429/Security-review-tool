using System.Text;
using System.Text.RegularExpressions;

namespace SecurityReview.Application.Scans;

internal sealed class ExclusionMatcher
{
    private readonly Regex[] _patterns;

    public ExclusionMatcher(IEnumerable<string> patterns)
    {
        ArgumentNullException.ThrowIfNull(patterns);
        _patterns = patterns
            .Where(pattern => !string.IsNullOrWhiteSpace(pattern))
            .Select(pattern => new Regex(
                ToRegex(pattern),
                RegexOptions.CultureInvariant
                | RegexOptions.IgnoreCase
                | RegexOptions.NonBacktracking))
            .ToArray();
    }

    public bool IsMatch(string relativePath, string? streamName)
    {
        string normalized = relativePath.Replace('\\', '/').TrimStart('/');
        if (streamName is not null)
        {
            normalized += ":" + streamName;
        }

        return _patterns.Any(pattern => pattern.IsMatch(normalized));
    }

    private static string ToRegex(string glob)
    {
        string normalized = glob.Replace('\\', '/').TrimStart('/');
        var regex = new StringBuilder(normalized.Length * 2 + 2);
        regex.Append('^');
        for (int i = 0; i < normalized.Length; i++)
        {
            char current = normalized[i];
            if (current == '*')
            {
                bool recursive = i + 1 < normalized.Length
                    && normalized[i + 1] == '*';
                if (recursive)
                {
                    i++;
                    regex.Append(".*");
                }
                else
                {
                    regex.Append("[^/]*");
                }
            }
            else if (current == '?')
            {
                regex.Append("[^/]");
            }
            else
            {
                regex.Append(Regex.Escape(current.ToString()));
            }
        }

        regex.Append('$');
        return regex.ToString();
    }
}
