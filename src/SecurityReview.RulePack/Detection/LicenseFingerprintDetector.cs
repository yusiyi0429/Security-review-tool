using System.Text.RegularExpressions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects license, copyright, SPDX, and vendor markers in text content.
///
/// Matches bounded license/copyright/SPDX/vendor markers. Without a matching
/// authorization from the manifest and rule package, emits SENS-008 with
/// <c>RequiresManualVerification=true</c> and conclusion key
/// <c>suspected_restricted_third_party_content</c>.
///
/// Never sets a legal or infringement boolean — that determination is out of scope.
/// </summary>
public sealed partial class LicenseFingerprintDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.LicenseFingerprint;

    // License keyword patterns
    [GeneratedRegex(@"\b(?:LICENSE|LICENCE|SPDX-License-Identifier|Copyright\s*[©(]\s*\d{4})",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex LicenseKeywordPattern();

    // Full copyright line
    [GeneratedRegex(@"Copyright\s*(?:\([cC]\)|©)?\s*\d{4}(?:\s*-\s*\d{4})?\s+[^\n]{3,100}",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex CopyrightLinePattern();

    // SPDX identifier
    [GeneratedRegex(@"SPDX-License-Identifier:\s*([a-zA-Z0-9.\-+]+)",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex SpdxPattern();

    // License file markers
    [GeneratedRegex(@"\b(?:MIT|Apache|GPL|LGPL|BSD|MPL|AGPL|EPL|CDDL|UNLICENSE)\s+(?:License|LICENSE)",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex NamedLicensePattern();

    // Vendor/supplier markers
    [GeneratedRegex(@"\b(?:Proprietary|Confidential|All\s+Rights\s+Reserved|Trade\s+Secret)",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex VendorMarkerPattern();

    /// <summary>
    /// Authorization entries from the manifest and rule package.
    /// Each entry maps a license/SPDX identifier to authorized scope (time, asset scope).
    /// </summary>
    public sealed record LicenseAuthorization
    {
        public required string LicenseId { get; init; }
        public required string AuthorizedAssetScope { get; init; }
        public DateTimeOffset? AuthorizedUntil { get; init; }
        public string? AuthorizationId { get; init; }
    }

    private readonly IReadOnlyList<LicenseAuthorization> _authorizations;
    private readonly string _currentAssetScope;

    /// <summary>
    /// Create a license fingerprint detector.
    /// </summary>
    /// <param name="authorizations">
    /// Authorized licenses from the manifest/rule package. Empty list means
    /// all license matches are flagged.
    /// </param>
    /// <param name="currentAssetScope">The current asset scope for authorization matching.</param>
    public LicenseFingerprintDetector(
        IReadOnlyList<LicenseAuthorization> authorizations,
        string currentAssetScope = "")
    {
        _authorizations = authorizations ?? Array.Empty<LicenseAuthorization>();
        _currentAssetScope = currentAssetScope ?? "";
    }

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

        if (chunk.ContentKind == ContentKind.Binary)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        int limit = detector.MaxMatchesPerChunk;
        string text = chunk.Text;
        var results = new List<DetectionCandidate>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // Scan for license-related markers
        ScanPattern(chunk, rule, detector, LicenseKeywordPattern(), text, ref limit, results, seen);
        ScanPattern(chunk, rule, detector, CopyrightLinePattern(), text, ref limit, results, seen);
        ScanPattern(chunk, rule, detector, SpdxPattern(), text, ref limit, results, seen);
        ScanPattern(chunk, rule, detector, NamedLicensePattern(), text, ref limit, results, seen);
        ScanPattern(chunk, rule, detector, VendorMarkerPattern(), text, ref limit, results, seen);

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }

    private void ScanPattern(
        ContentChunk chunk,
        RuleDefinition rule,
        DetectorDefinition detector,
        Regex regex,
        string text,
        ref int remaining,
        List<DetectionCandidate> results,
        HashSet<string> seen)
    {
        foreach (var match in regex.EnumerateMatches(text))
        {
            if (remaining <= 0) return;

            string value = text.Substring(match.Index, match.Length);
            if (!seen.Add(value)) continue;

            // Check against authorizations
            bool isAuthorized = IsAuthorized(value);

            if (!isAuthorized)
            {
                var locator = new SourceLocator.TextLocator(0, match.Index,
                    chunk.SourceStart + match.Index, match.Length);

                string context = ExtractContext(text, match.Index, match.Length);

                var candidate = DetectionCandidate.Create(
                    value, context, locator,
                    rule.Id, detector.Id,
                    rule.Severity, DetectionConfidence.High,
                    rule.FindingKind,
                    requiresSemanticReview: true); // SENS-008 always requires manual verification

                results.Add(candidate);
                remaining--;
            }
        }
    }

    /// <summary>
    /// Check whether a matched license/copyright marker has a matching authorization.
    /// </summary>
    internal bool IsAuthorized(string matchValue)
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var auth in _authorizations)
        {
            // Check scope
            if (!string.IsNullOrEmpty(auth.AuthorizedAssetScope) &&
                !string.Equals(auth.AuthorizedAssetScope, _currentAssetScope, StringComparison.OrdinalIgnoreCase) &&
                auth.AuthorizedAssetScope != "*")
                continue;

            // Check expiry
            if (auth.AuthorizedUntil.HasValue && auth.AuthorizedUntil.Value <= now)
                continue;

            // Check license ID match (substring match in the value)
            if (matchValue.Contains(auth.LicenseId, StringComparison.OrdinalIgnoreCase))
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
