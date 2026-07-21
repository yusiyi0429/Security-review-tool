using System.Security.Cryptography;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects signed content fingerprints (hashes of known third-party files/components).
///
/// Without a matching authorization from the manifest and rule package, emits SENS-008
/// with <c>RequiresManualVerification=true</c> and conclusion key
/// <c>suspected_restricted_third_party_content</c>.
/// </summary>
public sealed class ContentFingerprintDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.ContentFingerprint;

    /// <summary>
    /// A signed content fingerprint entry from the rule package.
    /// </summary>
    public sealed record FingerprintEntry
    {
        public required string FingerprintId { get; init; }
        public required string Algorithm { get; init; }  // sha256, sha512, etc.
        public required string HashValue { get; init; }   // hex-encoded
        public required string ComponentName { get; init; }
        public string? Version { get; init; }
    }

    /// <summary>
    /// Authorization for a specific fingerprint.
    /// </summary>
    public sealed record FingerprintAuthorization
    {
        public required string FingerprintId { get; init; }
        public required string AuthorizationId { get; init; }
        public required string AuthorizedAssetScope { get; init; }
        public DateTimeOffset? AuthorizedUntil { get; init; }
    }

    private readonly IReadOnlyList<FingerprintEntry> _fingerprints;
    private readonly IReadOnlyList<FingerprintAuthorization> _authorizations;
    private readonly string _currentAssetScope;

    public ContentFingerprintDetector(
        IReadOnlyList<FingerprintEntry> fingerprints,
        IReadOnlyList<FingerprintAuthorization> authorizations,
        string currentAssetScope = "")
    {
        _fingerprints = fingerprints ?? Array.Empty<FingerprintEntry>();
        _authorizations = authorizations ?? Array.Empty<FingerprintAuthorization>();
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

        if (_fingerprints.Count == 0)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        int limit = detector.MaxMatchesPerChunk;
        var results = new List<DetectionCandidate>();

        // Compute hashes of the chunk text for each algorithm
        byte[] textBytes = Encoding.UTF8.GetBytes(chunk.Text);

        foreach (var fp in _fingerprints)
        {
            if (results.Count >= limit) break;

            cancellationToken.ThrowIfCancellationRequested();

            string computedHash = ComputeHash(textBytes, fp.Algorithm);

            if (string.Equals(computedHash, fp.HashValue, StringComparison.OrdinalIgnoreCase))
            {
                // Check authorization
                bool isAuthorized = IsAuthorized(fp.FingerprintId);

                if (!isAuthorized)
                {
                    var locator = new SourceLocator.TextLocator(0, 0,
                        chunk.SourceStart, chunk.Text.Length);

                    string context = $"Content fingerprint match: {fp.ComponentName}";

                    var candidate = DetectionCandidate.Create(
                        fp.ComponentName,
                        context,
                        locator,
                        rule.Id, detector.Id,
                        rule.Severity, DetectionConfidence.High,
                        rule.FindingKind,
                        requiresSemanticReview: true);

                    results.Add(candidate);
                }
            }
        }

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }

    private bool IsAuthorized(string fingerprintId)
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var auth in _authorizations)
        {
            if (!string.Equals(auth.FingerprintId, fingerprintId, StringComparison.Ordinal))
                continue;

            if (!string.IsNullOrEmpty(auth.AuthorizedAssetScope) &&
                !string.Equals(auth.AuthorizedAssetScope, _currentAssetScope, StringComparison.OrdinalIgnoreCase) &&
                auth.AuthorizedAssetScope != "*")
                continue;

            if (auth.AuthorizedUntil.HasValue && auth.AuthorizedUntil.Value <= now)
                continue;

            return true;
        }

        return false;
    }

    private static string ComputeHash(byte[] data, string algorithm)
    {
        byte[] hash = algorithm.ToLowerInvariant() switch
        {
            "sha256" => SHA256.HashData(data),
            "sha384" => SHA384.HashData(data),
            "sha512" => SHA512.HashData(data),
            // MD5 intentionally excluded — not approved for security reviews
            _ => SHA256.HashData(data)
        };

        return Convert.ToHexStringLower(hash);
    }
}
