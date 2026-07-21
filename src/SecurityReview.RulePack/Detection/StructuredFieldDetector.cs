using System.Collections.Frozen;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Detects sensitive data in structured fields (JSON properties, headers, metadata).
/// Matches against parser-provided property/header/metadata path using normalized
/// key dictionaries (password, token, secret, and equivalents).
/// Does NOT rely on text regex alone — works with structured paths.
/// </summary>
public sealed class StructuredFieldDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.StructuredField;

    // Normalized sensitive key names (case-insensitive)
    private static readonly FrozenSet<string> SensitiveKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "pwd", "passcode",
        "token", "access_token", "access-token", "auth_token", "auth-token",
        "secret", "api_secret", "api-secret", "client_secret", "client-secret",
        "apikey", "api_key", "api-key",
        "private_key", "private-key", "privatekey",
        "connection_string", "connectionstring", "connstr",
        "authorization", "auth",
        "credential", "credentials",
        "jwt", "bearer",
        "certificate", "cert",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

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

        // This detector works with structured data (StructuredData or Metadata content kinds)
        if (chunk.ContentKind != ContentKind.StructuredData &&
            chunk.ContentKind != ContentKind.Metadata)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        int limit = detector.MaxMatchesPerChunk;

        // Look at the virtual path: path segments that match sensitive keys
        // e.g., "config.json#/database/password" → "password" is sensitive
        var results = new List<DetectionCandidate>();

        // Extract property names from the virtual path
        string path = chunk.VirtualPath;
        var segments = path.Split(['/', '#', '.', '!'], StringSplitOptions.RemoveEmptyEntries);

        foreach (string segment in segments)
        {
            if (limit <= 0) break;

            if (!SensitiveKeys.Contains(segment)) continue;

            // Check if there's a non-empty value in the chunk text
            string text = chunk.Text.Trim();
            if (text.Length == 0) continue;

            string truncatedValue = text.Length > 100 ? text[..100] : text;
            var locator = new SourceLocator.PathLocator(
                PathKind.Segment,
                string.Join('/', segments));

            var candidate = DetectionCandidate.Create(
                truncatedValue, "", locator,
                rule.Id, detector.Id,
                rule.Severity, DetectionConfidence.High,
                rule.FindingKind, rule.RequiresSemanticReview);

            results.Add(candidate);
            limit--;
        }

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }
}
