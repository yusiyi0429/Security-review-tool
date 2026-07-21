using System.Text.RegularExpressions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects candidates with checksum validation (Luhn, Chinese ID).
/// Valid checksums elevate confidence; format-only hits without checksum
/// verification remain at lower confidence. Severity always comes from policy.
/// </summary>
public sealed partial class ChecksumDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.Checksum;

    // 18-digit Chinese ID pattern (basic structural match)
    [GeneratedRegex(@"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex ChineseIdPattern();

    // Luhn-eligible digit sequences (13-19 digits)
    [GeneratedRegex(@"\b\d{13,19}\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex LuhnCandidatePattern();

    // Chinese ID checksum weights
    private static readonly int[] CnIdWeights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    private static readonly char[] CnIdCheckChars = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

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

        string algorithm = detector.Parameters.TryGetValue("algorithm", out string? alg)
            ? alg
            : "luhn";

        var candidates = algorithm switch
        {
            "luhn" => DetectLuhn(chunk, rule, detector),
            "cnid" => DetectChineseId(chunk, rule, detector),
            _ => Array.Empty<DetectionCandidate>()
        };

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(candidates);
    }

    private static DetectionCandidate[] DetectLuhn(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector)
    {
        string text = chunk.Text;
        int limit = detector.MaxMatchesPerChunk;

        var results = new List<DetectionCandidate>();
        var matches = LuhnCandidatePattern().EnumerateMatches(text);

        foreach (var match in matches)
        {
            if (results.Count >= limit) break;

            string value = text.Substring(match.Index, match.Length);
            bool valid = IsLuhnValid(value);

            DetectionConfidence confidence = valid
                ? DetectionConfidence.High
                : DetectionConfidence.Low;

            var locator = CreateTextLocator(chunk, match.Index, match.Length);
            var candidate = DetectionCandidate.Create(
                value, ExtractContext(text, match.Index, match.Length),
                locator, rule.Id, detector.Id,
                rule.Severity, confidence, rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
        }

        return results.ToArray();
    }

    private static DetectionCandidate[] DetectChineseId(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector)
    {
        string text = chunk.Text;
        int limit = detector.MaxMatchesPerChunk;

        var results = new List<DetectionCandidate>();
        var matches = ChineseIdPattern().EnumerateMatches(text);

        foreach (var match in matches)
        {
            if (results.Count >= limit) break;

            string value = text.Substring(match.Index, match.Length);

            // Validate date and checksum
            if (!IsValidChineseId(value)) continue;

            var locator = CreateTextLocator(chunk, match.Index, match.Length);
            var candidate = DetectionCandidate.Create(
                value, ExtractContext(text, match.Index, match.Length),
                locator, rule.Id, detector.Id,
                rule.Severity, DetectionConfidence.High, rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
        }

        return results.ToArray();
    }

    private static bool IsLuhnValid(string digits)
    {
        int sum = 0;
        bool alternate = false;

        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int digit = digits[i] - '0';
            if (alternate)
            {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }

            sum += digit;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }

    internal static bool IsValidChineseId(string id)
    {
        if (id.Length != 18) return false;

        // Validate region code (first 6 digits): synthetic range 110000-659999
        if (!int.TryParse(id.AsSpan(0, 6), out int region) || region < 110000 || region > 659999)
            return false;

        // Validate birth date
        if (!int.TryParse(id.AsSpan(6, 4), out int year)) return false;
        if (!int.TryParse(id.AsSpan(10, 2), out int month)) return false;
        if (!int.TryParse(id.AsSpan(12, 2), out int day)) return false;

        if (year < 1900 || year > 2099) return false;
        if (month < 1 || month > 12) return false;
        if (day < 1 || day > 31) return false;

        // Days-in-month validation
        if (day > DateTime.DaysInMonth(year, month)) return false;

        // Validate checksum
        int sum = 0;
        for (int i = 0; i < 17; i++)
        {
            sum += (id[i] - '0') * CnIdWeights[i];
        }

        char expected = CnIdCheckChars[sum % 11];
        char actual = char.ToUpperInvariant(id[17]);
        return expected == actual;
    }

    private static SourceLocator.TextLocator CreateTextLocator(ContentChunk chunk, int matchIndex, int matchLength)
    {
        // Use the first location map entry to approximate source offset
        long sourceOffset = chunk.SourceStart;
        if (chunk.LocationMap.Count > 0)
        {
            var entry = chunk.LocationMap[0];
            sourceOffset = entry.SourceStart + matchIndex;
        }
        else
        {
            sourceOffset = chunk.SourceStart + matchIndex;
        }

        return new SourceLocator.TextLocator(0, matchIndex, sourceOffset, matchLength);
    }

    private static string ExtractContext(string text, int matchIndex, int matchLength)
    {
        int contextStart = Math.Max(0, matchIndex - 20);
        int contextEnd = Math.Min(text.Length, matchIndex + matchLength + 20);
        return text[contextStart..contextEnd];
    }
}
