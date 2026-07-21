using System.Collections.Frozen;
using System.Text;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Controls how term normalization treats case differences during matching.
/// </summary>
public enum CaseNormalization
{
    /// <summary>Preserve original case; terms are matched as-is after NFKC.</summary>
    None,

    /// <summary>Fold to uppercase using the invariant culture.</summary>
    UpperInvariant,

    /// <summary>Fold to lowercase using the invariant culture.</summary>
    LowerInvariant,

    /// <summary>Fold using ordinal case-insensitive comparison rules.</summary>
    OrdinalIgnoreCase
}

/// <summary>
/// A matched term returned by <see cref="AhoCorasickMatcher"/>. Overlapping matches
/// are preserved; grouping is the caller's responsibility.
/// </summary>
public sealed record AhoCorasickMatch
{
    public int NormalizedStart { get; init; }
    public int NormalizedLength { get; init; }
    public int TermId { get; init; }
    public IReadOnlyList<string> Payloads { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Resource bounds for constructing an Aho-Corasick automaton.
/// The automaton is rejected before allocation when any bound is exceeded.
/// </summary>
public sealed record AhoCorasickBounds
{
    public const int DefaultMaxTerms = 100_000;
    public const int DefaultMaxTotalNormalizedBytes = 32 * 1024 * 1024; // 32 MiB
    public const int DefaultMaxCharsPerTerm = 512;
    public const long DefaultMaxAutomatonEstimateBytes = 128 * 1024 * 1024; // 128 MiB

    public int MaxTerms { get; init; } = DefaultMaxTerms;
    public int MaxTotalNormalizedBytes { get; init; } = DefaultMaxTotalNormalizedBytes;
    public int MaxCharsPerTerm { get; init; } = DefaultMaxCharsPerTerm;
    public long MaxAutomatonEstimateBytes { get; init; } = DefaultMaxAutomatonEstimateBytes;
}

/// <summary>
/// Immutable Aho-Corasick automaton built at policy load from a set of normalized terms.
///
/// Each term is associated with one or more payload strings (e.g., entity IDs, rule IDs).
/// The automaton is constructed once and reused across all chunks.
/// </summary>
public sealed class AhoCorasickMatcher
{
    private sealed class TrieNode
    {
        public FrozenDictionary<char, TrieNode>? Goto;
        public TrieNode? Failure;
        public int Depth;
        public List<(int TermId, IReadOnlyList<string> Payloads)>? Output;
    }

    private readonly TrieNode _root;
    private readonly CaseNormalization _caseMode;

    private AhoCorasickMatcher(TrieNode root, CaseNormalization caseMode)
    {
        _root = root;
        _caseMode = caseMode;
    }

    /// <summary>
    /// Build an immutable Aho-Corasick automaton from the provided terms.
    /// </summary>
    /// <param name="entries">Tuples of (original term, term ID, payloads).</param>
    /// <param name="caseMode">Case normalization for matching.</param>
    /// <param name="bounds">Resource limits; validated before allocation.</param>
    /// <exception cref="AhoCorasickBuildException">A resource bound was exceeded.</exception>
    public static AhoCorasickMatcher Build(
        IReadOnlyList<(string Original, int TermId, IReadOnlyList<string> Payloads)> entries,
        CaseNormalization caseMode,
        AhoCorasickBounds? bounds = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        bounds ??= new AhoCorasickBounds();

        if (entries.Count > bounds.MaxTerms)
            throw new AhoCorasickBuildException(
                $"Term count {entries.Count} exceeds maximum {bounds.MaxTerms}.");

        int totalUtf8Bytes = 0;

        for (int i = 0; i < entries.Count; i++)
        {
            string original = entries[i].Original;
            if (string.IsNullOrEmpty(original))
                throw new ArgumentException($"Entry {i} has null or empty term.", nameof(entries));

            if (original.Length > bounds.MaxCharsPerTerm)
                throw new AhoCorasickBuildException(
                    $"Term length {original.Length} exceeds maximum {bounds.MaxCharsPerTerm}.");

            string normalized = Normalize(original, caseMode);
            totalUtf8Bytes += Encoding.UTF8.GetByteCount(normalized);

            if (totalUtf8Bytes > bounds.MaxTotalNormalizedBytes)
                throw new AhoCorasickBuildException(
                    $"Total normalized UTF-8 bytes {totalUtf8Bytes} exceeds maximum {bounds.MaxTotalNormalizedBytes}.");
        }

        // Estimate automaton size: each character adds roughly one node,
        // each node ~80 bytes (key + child pointer + failure + depth + overhead).
        int totalChars = 0;
        foreach (var entry in entries)
            totalChars += Normalize(entry.Original, caseMode).Length;

        long estimate = totalChars * 80L + entries.Count * 32L;
        if (estimate > bounds.MaxAutomatonEstimateBytes)
            throw new AhoCorasickBuildException(
                $"Estimated automaton footprint {estimate} bytes exceeds maximum {bounds.MaxAutomatonEstimateBytes}.");

        return BuildTrie(entries, caseMode);
    }

    private static AhoCorasickMatcher BuildTrie(
        IReadOnlyList<(string Original, int TermId, IReadOnlyList<string> Payloads)> entries,
        CaseNormalization caseMode)
    {
        // Phase 1: insert all normalized terms into the goto trie
        var root = new TrieNode();
        var nodeList = new List<TrieNode> { root };

        for (int i = 0; i < entries.Count; i++)
        {
            string normalized = Normalize(entries[i].Original, caseMode);
            TrieNode current = root;

            foreach (char c in normalized)
            {
                current.Goto ??= new Dictionary<char, TrieNode>().ToFrozenDictionary();

                // Need mutable access — use a builder pattern
                // FrozenDictionary is immutable; we'll build with regular Dictionary first
                break;
            }
        }

        // The above approach won't work with FrozenDictionary for mutable inserts.
        // Let's build with Dictionary first, then freeze at the end.

        return BuildWithMutableTrie(entries, caseMode);
    }

    private static AhoCorasickMatcher BuildWithMutableTrie(
        IReadOnlyList<(string Original, int TermId, IReadOnlyList<string> Payloads)> entries,
        CaseNormalization caseMode)
    {
        var root = new MutableTrieNode();

        // Insert all terms
        for (int i = 0; i < entries.Count; i++)
        {
            string normalized = Normalize(entries[i].Original, caseMode);
            MutableTrieNode current = root;

            for (int j = 0; j < normalized.Length; j++)
            {
                char c = normalized[j];

                if (!current.Goto.TryGetValue(c, out MutableTrieNode? next))
                {
                    next = new MutableTrieNode { Depth = current.Depth + 1 };
                    current.Goto[c] = next;
                }

                current = next;
            }

            current.Output ??= new List<(int, IReadOnlyList<string>)>();
            current.Output.Add((entries[i].TermId, entries[i].Payloads));
        }

        // Phase 2: build failure links via BFS
        var queue = new Queue<MutableTrieNode>();
        foreach (var kvp in root.Goto)
        {
            kvp.Value.Failure = root;
            queue.Enqueue(kvp.Value);
        }

        while (queue.Count > 0)
        {
            MutableTrieNode current = queue.Dequeue();

            foreach (var kvp in current.Goto)
            {
                char c = kvp.Key;
                MutableTrieNode child = kvp.Value;

                queue.Enqueue(child);

                MutableTrieNode? fail = current.Failure;
                while (fail != null && !fail.Goto.ContainsKey(c))
                    fail = fail.Failure;

                child.Failure = fail?.Goto.GetValueOrDefault(c, root) ?? root;

                // Merge outputs from failure link
                if (child.Failure?.Output is { Count: > 0 } failOut)
                {
                    child.Output ??= new List<(int, IReadOnlyList<string>)>();
                    child.Output.AddRange(failOut);
                }
            }
        }

        // Phase 3: freeze immutable trie
        var frozenRoot = Freeze(root);
        return new AhoCorasickMatcher(frozenRoot, caseMode);
    }

    /// <summary>
    /// Search text for all occurrences of inserted terms.
    /// Returns all overlapping matches; downstream grouping is the caller's job.
    /// </summary>
    public IReadOnlyList<AhoCorasickMatch> Search(string text, int maxMatches)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length == 0 || maxMatches < 1)
            return Array.Empty<AhoCorasickMatch>();

        string searchText = Normalize(text, _caseMode);
        var results = new List<AhoCorasickMatch>();

        TrieNode current = _root;

        for (int i = 0; i < searchText.Length; i++)
        {
            char c = searchText[i];

            while (current.Goto is null || !current.Goto.ContainsKey(c))
            {
                if (current == _root) break;
                current = current.Failure ?? _root;
            }

            if (current.Goto != null && current.Goto.TryGetValue(c, out TrieNode? next))
                current = next;

            // Collect all outputs at this node (including merged failure-chain outputs)
            if (current.Output is { Count: > 0 })
            {
                foreach (var (termId, payloads) in current.Output)
                {
                    if (results.Count >= maxMatches)
                        return results;

                    results.Add(new AhoCorasickMatch
                    {
                        NormalizedStart = i - current.Depth + 1,
                        NormalizedLength = current.Depth,
                        TermId = termId,
                        Payloads = payloads
                    });
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Normalize text: NFKC normalization followed by case folding per the mode.
    /// </summary>
    public static string Normalize(string text, CaseNormalization caseMode)
    {
        string nfkc = text.IsNormalized(NormalizationForm.FormKC)
            ? text
            : text.Normalize(NormalizationForm.FormKC);

        return caseMode switch
        {
            CaseNormalization.None => nfkc,
            CaseNormalization.UpperInvariant => nfkc.ToUpperInvariant(),
            CaseNormalization.LowerInvariant => nfkc.ToLowerInvariant(),
            CaseNormalization.OrdinalIgnoreCase => nfkc.ToUpperInvariant(),
            _ => nfkc
        };
    }

    private static TrieNode Freeze(MutableTrieNode mutableRoot)
    {
        var map = new Dictionary<MutableTrieNode, TrieNode>();

        // First pass: create frozen nodes
        var queue = new Queue<MutableTrieNode>();
        map[mutableRoot] = new TrieNode { Depth = 0 };
        queue.Enqueue(mutableRoot);

        while (queue.Count > 0)
        {
            var m = queue.Dequeue();
            var f = map[m];

            if (m.Output is { Count: > 0 })
                f.Output = [.. m.Output];

            if (m.Goto.Count > 0)
            {
                var frozenChildren = new Dictionary<char, TrieNode>(m.Goto.Count);

                foreach (var kvp in m.Goto)
                {
                    if (!map.TryGetValue(kvp.Value, out TrieNode? childFrozen))
                    {
                        childFrozen = new TrieNode { Depth = kvp.Value.Depth };
                        map[kvp.Value] = childFrozen;
                        queue.Enqueue(kvp.Value);
                    }

                    frozenChildren[kvp.Key] = childFrozen;
                }

                f.Goto = frozenChildren.ToFrozenDictionary();
            }
        }

        // Second pass: set failure links
        foreach (var (m, f) in map)
        {
            if (m.Failure != null && map.TryGetValue(m.Failure, out TrieNode? failFrozen))
                f.Failure = failFrozen;
        }

        return map[mutableRoot];
    }

    private sealed class MutableTrieNode
    {
        public readonly Dictionary<char, MutableTrieNode> Goto = new();
        public MutableTrieNode? Failure;
        public int Depth;
        public List<(int TermId, IReadOnlyList<string> Payloads)>? Output;
    }
}

/// <summary>
/// Thrown when the Aho-Corasick automaton cannot be built because a resource
/// bound is exceeded.
/// </summary>
public sealed class AhoCorasickBuildException : Exception
{
    public AhoCorasickBuildException(string message) : base(message) { }
}
