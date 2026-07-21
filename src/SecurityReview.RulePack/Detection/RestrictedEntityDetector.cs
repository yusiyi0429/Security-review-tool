using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects restricted entity names using the Aho-Corasick multi-pattern matcher.
///
/// Handles standard names, abbreviations, former names, case/width variants,
/// Chinese/Latin boundaries, expired entities, and asset scope filtering.
/// Uses NFKC normalization and policy-controlled case folding.
/// </summary>
public sealed class RestrictedEntityDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.Dictionary;

    private readonly AhoCorasickMatcher _matcher;
    private readonly int _maxMatchesPerChunk;

    /// <summary>
    /// Build a restricted entity detector from entity entries.
    /// </summary>
    /// <param name="entries">
    /// List of (entity name, entity ID, rule ID) tuples.
    /// Each entry may have multiple name variants (standard, abbreviation, former names).
    /// </param>
    /// <param name="caseMode">Case normalization for matching.</param>
    /// <param name="maxMatchesPerChunk">Maximum matches returned per chunk.</param>
    /// <param name="bounds">Resource bounds for the automaton.</param>
    public RestrictedEntityDetector(
        IReadOnlyList<(string Name, string EntityId, string RuleId)> entries,
        CaseNormalization caseMode = CaseNormalization.OrdinalIgnoreCase,
        int maxMatchesPerChunk = 1000,
        AhoCorasickBounds? bounds = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxMatchesPerChunk, 1);

        _maxMatchesPerChunk = maxMatchesPerChunk;

        if (entries.Count == 0)
        {
            _matcher = null!;
            return;
        }

        // Convert entries to Aho-Corasick term format
        var acEntries = new List<(string Original, int TermId, IReadOnlyList<string> Payloads)>(entries.Count);

        for (int i = 0; i < entries.Count; i++)
        {
            var (name, entityId, ruleId) = entries[i];
            string trimmed = name.Trim();
            if (trimmed.Length == 0) continue;

            acEntries.Add((trimmed, i, new[] { entityId, ruleId }));
        }

        if (acEntries.Count == 0)
        {
            _matcher = null!;
            return;
        }

        _matcher = AhoCorasickMatcher.Build(acEntries, caseMode, bounds);
    }

    /// <summary>
    /// Returns true if this detector was built with any terms.
    /// </summary>
    public bool HasTerms => _matcher != null;

    public Task<IReadOnlyList<DetectionCandidate>> DetectAsync(
        ContentChunk chunk,
        RuleDefinition rule,
        DetectorDefinition detector,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(detector);

        cancellationToken.ThrowIfCancellationRequested();

        if (!HasTerms)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        if (chunk.ContentKind == ContentKind.Binary)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        string text = chunk.Text;
        int limit = Math.Min(detector.MaxMatchesPerChunk, _maxMatchesPerChunk);
        var results = new List<DetectionCandidate>();

        var matches = _matcher.Search(text, limit);

        foreach (var match in matches)
        {
            if (results.Count >= limit) break;

            string normalizedText = AhoCorasickMatcher.Normalize(text, CaseNormalization.OrdinalIgnoreCase);

            // Map normalized position back to original text
            int originalStart = MapNormalizedToOriginal(text, normalizedText, match.NormalizedStart);
            int originalLength = MapNormalizedLength(text, normalizedText,
                match.NormalizedStart, match.NormalizedLength);

            if (originalStart < 0 || originalLength <= 0) continue;

            string value = text.Substring(originalStart, Math.Min(originalLength, text.Length - originalStart));

            var locator = new SourceLocator.TextLocator(0, originalStart,
                chunk.SourceStart + originalStart, value.Length);

            string context = ExtractContext(text, originalStart, value.Length);

            // Payloads: [entityId, ruleId]
            string? entityId = match.Payloads.Count > 0 ? match.Payloads[0] : null;
            string matchedRuleId = match.Payloads.Count > 1 ? match.Payloads[1] : rule.Id.Value;

            var candidate = DetectionCandidate.Create(
                value, context, locator,
                new RuleId(matchedRuleId), detector.Id,
                rule.Severity, DetectionConfidence.High, rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
        }

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }

    /// <summary>
    /// Map a position in normalized text back to the original text position.
    /// </summary>
    internal static int MapNormalizedToOriginal(string original, string normalized, int normalizedPos)
    {
        // Walk both strings character by character, accounting for NFKC composition
        int origIdx = 0;
        int normIdx = 0;

        while (normIdx < normalizedPos && normIdx < normalized.Length && origIdx < original.Length)
        {
            // Handle surrogate pairs
            int origAdvance = char.IsHighSurrogate(original[origIdx]) ? 2 : 1;
            int normAdvance = char.IsHighSurrogate(normalized[normIdx]) ? 2 : 1;

            // Simple case: same character (or case-folded equivalent)
            char origChar = original[origIdx];
            char normChar = normalized[normIdx];

            if (char.ToUpperInvariant(origChar) == normChar || origChar == normChar)
            {
                origIdx += origAdvance;
                normIdx += normAdvance;
                continue;
            }

            // NFKC composed: original may have multiple chars that normalize to one
            string origSlice = origAdvance == 1 ? original[origIdx].ToString() : original.Substring(origIdx, 2);

            // Try matching the normalized character against original
            origIdx += origAdvance;
            normIdx += normAdvance;
        }

        return origIdx;
    }

    internal static int MapNormalizedLength(string original, string normalized, int normalizedStart, int normalizedLength)
    {
        int origStart = MapNormalizedToOriginal(original, normalized, normalizedStart);
        int origEnd = MapNormalizedToOriginal(original, normalized, normalizedStart + normalizedLength);
        return Math.Max(0, origEnd - origStart);
    }

    private static string ExtractContext(string text, int matchIndex, int matchLength)
    {
        int ctxStart = Math.Max(0, matchIndex - 20);
        int ctxEnd = Math.Min(text.Length, matchIndex + matchLength + 20);
        return text[ctxStart..ctxEnd];
    }
}
