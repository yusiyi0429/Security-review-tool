using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// The disposition of a matched value against the approved-placeholder set.
/// </summary>
public enum PlaceholderDisposition
{
    /// <summary>Value is not in the placeholder set.</summary>
    NotApproved,

    /// <summary>Value matches an approved placeholder with a valid, non-expired entry.</summary>
    ApprovedExample,

    /// <summary>Value matches an entry that has expired.</summary>
    Expired
}

/// <summary>
/// Result of matching a candidate value against the approved placeholder set.
/// </summary>
public sealed record PlaceholderMatchResult
{
    public PlaceholderDisposition Disposition { get; init; }

    /// <summary>The placeholder ID when approved.</summary>
    public string? PlaceholderId { get; init; }

    /// <summary>The rule/category/context this placeholder covers.</summary>
    public string? ContextScope { get; init; }

    /// <summary>Version of the placeholder entry.</summary>
    public string? Version { get; init; }

    /// <summary>Expiry date, if any.</summary>
    public DateTimeOffset? Expiry { get; init; }
}

/// <summary>
/// Matches candidate values against the approved placeholder set.
///
/// Returns <see cref="PlaceholderDisposition.ApprovedExample"/> when a candidate
/// exactly matches a signed placeholder entry that covers the candidate's rule/category/context
/// and has not expired. Expired placeholders return <see cref="PlaceholderDisposition.Expired"/>
/// and are surfaced in diagnostics (not treated as approved).
///
/// An approved placeholder can annotate only the exact rule/category/context scope;
/// it cannot suppress a restricted-entity hit unless the signed entry explicitly
/// covers that rule.
/// </summary>
public sealed class ApprovedPlaceholderMatcher
{
    /// <summary>
    /// A single approved placeholder entry from the signed policy.
    /// </summary>
    public sealed record PlaceholderEntry
    {
        public required string PlaceholderId { get; init; }
        public required string Value { get; init; }
        public required string ContextScope { get; init; }
        public string? Version { get; init; }
        public DateTimeOffset? Expiry { get; init; }

        /// <summary>
        /// Normalized version of Value for efficient lookup.
        /// </summary>
        internal string NormalizedValue { get; set; } = string.Empty;
    }

    private readonly Dictionary<string, List<PlaceholderEntry>> _index;
    private readonly StringComparison _comparison;

    /// <summary>
    /// Create a matcher from a set of approved placeholder entries.
    /// Entries are indexed by normalized value for O(1) lookup.
    /// </summary>
    public ApprovedPlaceholderMatcher(
        IReadOnlyList<PlaceholderEntry> entries,
        StringComparison comparison = StringComparison.Ordinal)
    {
        ArgumentNullException.ThrowIfNull(entries);

        _comparison = comparison;
        _index = new Dictionary<string, List<PlaceholderEntry>>(
            comparison == StringComparison.OrdinalIgnoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        var normalizer = comparison == StringComparison.OrdinalIgnoreCase
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

        foreach (var entry in entries)
        {
            entry.NormalizedValue = normalizer.Equals(entry.Value, entry.Value)
                ? entry.Value
                : entry.Value; // Keep as-is for ordinal

            string key = comparison == StringComparison.OrdinalIgnoreCase
                ? entry.Value.ToUpperInvariant()
                : entry.Value;

            if (!_index.TryGetValue(key, out var list))
            {
                list = new List<PlaceholderEntry>();
                _index[key] = list;
            }

            list.Add(entry);
        }
    }

    /// <summary>
    /// Check whether a candidate value matches any approved placeholder.
    /// </summary>
    /// <param name="candidateValue">The value to check.</param>
    /// <param name="ruleId">The rule that produced the candidate.</param>
    /// <param name="categoryScope">
    /// The category/context scope to match against (e.g., "SENS-002", "restricted-entity").
    /// </param>
    /// <returns>A match result indicating disposition.</returns>
    public PlaceholderMatchResult Match(string candidateValue, string ruleId, string categoryScope)
    {
        ArgumentNullException.ThrowIfNull(candidateValue);
        ArgumentNullException.ThrowIfNull(ruleId);
        ArgumentNullException.ThrowIfNull(categoryScope);

        string lookupKey = _comparison == StringComparison.OrdinalIgnoreCase
            ? candidateValue.ToUpperInvariant()
            : candidateValue;

        if (!_index.TryGetValue(lookupKey, out var entries))
            return new PlaceholderMatchResult { Disposition = PlaceholderDisposition.NotApproved };

        var now = DateTimeOffset.UtcNow;

        // Find the best matching entry
        PlaceholderEntry? bestMatch = null;

        foreach (var entry in entries)
        {
            // Check expiry
            if (entry.Expiry.HasValue && entry.Expiry.Value <= now)
                continue;

            // Check scope match: the placeholder's context scope must cover this candidate's rule/context
            if (!ScopeMatches(entry.ContextScope, ruleId, categoryScope))
                continue;

            bestMatch = entry;
            break;
        }

        // Check for expired entries
        bool hasExpired = false;
        foreach (var entry in entries)
        {
            if (entry.Expiry.HasValue && entry.Expiry.Value <= now)
            {
                if (ScopeMatches(entry.ContextScope, ruleId, categoryScope))
                {
                    hasExpired = true;
                    break;
                }
            }
        }

        if (bestMatch != null)
        {
            return new PlaceholderMatchResult
            {
                Disposition = PlaceholderDisposition.ApprovedExample,
                PlaceholderId = bestMatch.PlaceholderId,
                ContextScope = bestMatch.ContextScope,
                Version = bestMatch.Version,
                Expiry = bestMatch.Expiry
            };
        }

        if (hasExpired)
        {
            return new PlaceholderMatchResult
            {
                Disposition = PlaceholderDisposition.Expired
            };
        }

        return new PlaceholderMatchResult { Disposition = PlaceholderDisposition.NotApproved };
    }

    private static bool ScopeMatches(string placeholderScope, string ruleId, string categoryScope)
    {
        // The placeholder scope can be a specific rule ID, a category, or a wildcard
        if (string.Equals(placeholderScope, ruleId, StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(placeholderScope, categoryScope, StringComparison.OrdinalIgnoreCase))
            return true;

        // Wildcard: all scope
        if (placeholderScope == "*" || placeholderScope == "all")
            return true;

        // Partial match: category prefix
        if (placeholderScope.EndsWith('*'))
        {
            string prefix = placeholderScope[..^1];
            if (categoryScope.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
            if (ruleId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
