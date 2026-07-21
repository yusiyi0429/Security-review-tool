using System.Text.RegularExpressions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects known sensitive data formats: token prefixes, private-key headers,
/// phone numbers, and policy-provided patterns. Format-only matches (no internal
/// checksum/context validation) receive lower confidence.
/// </summary>
public sealed partial class KnownFormatDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.KnownFormat;

    // Private key headers
    [GeneratedRegex(@"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY(?: BLOCK)?-----",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex PrivateKeyHeaderPattern();

    // Token/API key prefix patterns
    [GeneratedRegex(@"\b(?:sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36,}|xox[bpras]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16})\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex TokenPrefixPattern();

    // Chinese phone number
    [GeneratedRegex(@"\b1[3-9]\d{9}\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex PhonePattern();

    // Generic hex/base64-like token (long random-looking strings)
    [GeneratedRegex(@"\b[a-zA-Z0-9+/=_-]{20,}\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex LongTokenPattern();

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

        string format = detector.Parameters.TryGetValue("format", out string? fmt)
            ? fmt
            : "all";

        var candidates = format switch
        {
            "private_key" => ScanPattern(chunk, rule, detector, PrivateKeyHeaderPattern(), DetectionConfidence.High),
            "token" => ScanPattern(chunk, rule, detector, TokenPrefixPattern(), DetectionConfidence.High),
            "phone" => ScanPattern(chunk, rule, detector, PhonePattern(), DetectionConfidence.Medium),
            "long_token" => ScanPattern(chunk, rule, detector, LongTokenPattern(), DetectionConfidence.Low),
            "policy_pattern" => ScanPolicyPattern(chunk, rule, detector),
            "all" => ScanAllFormats(chunk, rule, detector),
            _ => Array.Empty<DetectionCandidate>()
        };

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(candidates);
    }

    private static DetectionCandidate[] ScanAllFormats(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector)
    {
        var all = new List<DetectionCandidate>();
        int limit = detector.MaxMatchesPerChunk;

        all.AddRange(ScanPatternLimited(chunk, rule, detector, PrivateKeyHeaderPattern(),
            DetectionConfidence.High, ref limit));
        all.AddRange(ScanPatternLimited(chunk, rule, detector, TokenPrefixPattern(),
            DetectionConfidence.High, ref limit));
        all.AddRange(ScanPatternLimited(chunk, rule, detector, PhonePattern(),
            DetectionConfidence.Medium, ref limit));
        all.AddRange(ScanPatternLimited(chunk, rule, detector, LongTokenPattern(),
            DetectionConfidence.Low, ref limit));
        all.AddRange(ScanPolicyPatternLimited(chunk, rule, detector, ref limit));

        return all.ToArray();
    }

    private static DetectionCandidate[] ScanPattern(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector,
        Regex regex, DetectionConfidence baseConfidence)
    {
        int limit = detector.MaxMatchesPerChunk;
        return ScanPatternLimited(chunk, rule, detector, regex, baseConfidence, ref limit);
    }

    private static DetectionCandidate[] ScanPatternLimited(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector,
        Regex regex, DetectionConfidence baseConfidence, ref int remaining)
    {
        string text = chunk.Text;
        var results = new List<DetectionCandidate>();

        foreach (var match in regex.EnumerateMatches(text))
        {
            if (remaining <= 0) break;

            string value = text.Substring(match.Index, match.Length);
            var locator = CreateTextLocator(chunk, match.Index, match.Length);
            string context = ExtractContext(text, match.Index, match.Length);

            var candidate = DetectionCandidate.Create(
                value, context, locator,
                rule.Id, detector.Id,
                rule.Severity, baseConfidence, rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
            remaining--;
        }

        return results.ToArray();
    }

    private static DetectionCandidate[] ScanPolicyPattern(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector)
    {
        int limit = detector.MaxMatchesPerChunk;
        return ScanPolicyPatternLimited(chunk, rule, detector, ref limit);
    }

    private static DetectionCandidate[] ScanPolicyPatternLimited(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector, ref int remaining)
    {
        if (!detector.Parameters.TryGetValue("pattern", out string? pattern) || string.IsNullOrEmpty(pattern))
            return [];

        var results = new List<DetectionCandidate>();

        try
        {
            Regex regex = SafeRegexFactory.Create(pattern);
            string text = chunk.Text;

            foreach (var match in regex.EnumerateMatches(text))
            {
                if (remaining <= 0) break;

                string value = text.Substring(match.Index, match.Length);
                var locator = CreateTextLocator(chunk, match.Index, match.Length);
                string context = ExtractContext(text, match.Index, match.Length);

                var candidate = DetectionCandidate.Create(
                    value, context, locator,
                    rule.Id, detector.Id,
                    rule.Severity, DetectionConfidence.Medium,
                    rule.FindingKind, rule.RequiresSemanticReview);

                results.Add(candidate);
                remaining--;
            }
        }
        catch (ArgumentException)
        {
            // Invalid pattern → no results
        }

        return results.ToArray();
    }

    private static SourceLocator.TextLocator CreateTextLocator(ContentChunk chunk, int matchIndex, int matchLength)
    {
        long sourceOffset = chunk.SourceStart + matchIndex;
        return new SourceLocator.TextLocator(0, matchIndex, sourceOffset, matchLength);
    }

    private static string ExtractContext(string text, int matchIndex, int matchLength)
    {
        int ctxStart = Math.Max(0, matchIndex - 20);
        int ctxEnd = Math.Min(text.Length, matchIndex + matchLength + 20);
        return text[ctxStart..ctxEnd];
    }
}
