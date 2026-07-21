using System.Collections.Frozen;
using System.Text.RegularExpressions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Computes Shannon entropy on token-like sequences (16–512 characters) and
/// requires nearby credential context (e.g., "password", "secret", "token")
/// unless policy explicitly defines a strong format.
/// Skips binary chunks already covered by known-format detectors.
/// </summary>
public sealed partial class EntropyContextDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.EntropyWithContext;

    // Token-like candidates: minimum 16, max 512 chars
    [GeneratedRegex(@"\b\S{16,512}\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex TokenCandidatePattern();

    // Credential context keywords
    private static readonly FrozenSet<string> CredentialContextKeywords =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "password", "passwd", "pwd", "passcode",
            "token", "secret", "key", "apikey", "api_key",
            "auth", "authorization", "bearer",
            "credential", "credentials",
            "private", "signing", "encryption",
            "BEGIN", "PRIVATE KEY",
        }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    // Min entropy threshold for suspicious tokens (bits per character)
    private const double MinEntropyPerChar = 3.5;

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

        // Skip binary chunks — already covered by known-format detectors
        if (chunk.ContentKind == ContentKind.Binary)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        // Check if policy defines a strong format → always scan
        bool strongFormat = detector.Parameters.TryGetValue("strong_format", out string? sf)
            && string.Equals(sf, "true", StringComparison.OrdinalIgnoreCase);

        int limit = detector.MaxMatchesPerChunk;
        string text = chunk.Text;
        var results = new List<DetectionCandidate>();

        foreach (var match in TokenCandidatePattern().EnumerateMatches(text))
        {
            if (results.Count >= limit) break;

            string value = text.Substring(match.Index, match.Length);

            // Skip if value is mostly ASCII digits or hex
            if (IsLowComplexity(value)) continue;

            double entropy = ShannonEntropy(value);

            if (entropy < MinEntropyPerChar && !strongFormat) continue;

            // Check for nearby credential context
            bool hasCredentialContext = strongFormat || HasCredentialContext(text, match.Index, match.Length);

            DetectionConfidence confidence = hasCredentialContext
                ? DetectionConfidence.Medium
                : DetectionConfidence.Low;

            var locator = new SourceLocator.TextLocator(0, match.Index,
                chunk.SourceStart + match.Index, match.Length);
            string context = ExtractContext(text, match.Index, match.Length);

            var candidate = DetectionCandidate.Create(
                value, context, locator,
                rule.Id, detector.Id,
                rule.Severity, confidence, rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
        }

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }

    /// <summary>
    /// Compute Shannon entropy in bits per character.
    /// </summary>
    internal static double ShannonEntropy(string value)
    {
        if (value.Length == 0) return 0;

        Span<int> counts = stackalloc int[256];
        counts.Clear();

        foreach (char c in value)
        {
            if (c < 256) counts[c]++;
        }

        double entropy = 0;
        double len = value.Length;
        foreach (int count in counts)
        {
            if (count == 0) continue;
            double p = count / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static bool IsLowComplexity(string value)
    {
        int digitCount = 0;
        int hexCount = 0;
        foreach (char c in value)
        {
            if (char.IsDigit(c)) digitCount++;
            if (char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                hexCount++;
        }

        // More than 80% digits → likely a numeric ID, not a secret
        if ((double)digitCount / value.Length > 0.8) return true;

        // More than 90% hex → likely a hash or non-secret hex
        if ((double)hexCount / value.Length > 0.9) return true;

        return false;
    }

    private static bool HasCredentialContext(string text, int matchIndex, int matchLength)
    {
        // Search in a window of ±100 chars around the match
        int windowStart = Math.Max(0, matchIndex - 100);
        int windowEnd = Math.Min(text.Length, matchIndex + matchLength + 100);
        string window = text[windowStart..windowEnd];

        foreach (string keyword in CredentialContextKeywords)
        {
            if (window.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string ExtractContext(string text, int matchIndex, int matchLength)
    {
        int ctxStart = Math.Max(0, matchIndex - 30);
        int ctxEnd = Math.Min(text.Length, matchIndex + matchLength + 30);
        return text[ctxStart..ctxEnd];
    }
}
