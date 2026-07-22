using System.Text.RegularExpressions;

namespace SecurityReview.Infrastructure.Diagnostics;

/// <summary>
/// Enforces the allowlist/blacklist policy for diagnostic field names and
/// values. Every field key and every string value is checked before a
/// diagnostic event is accepted by the sink or exported in a support bundle.
///
/// Allowlist: stable, non-PII identifiers — event code, UTC timestamp, scan
/// UUID, stage, reason/status code, numeric counts/durations, module/method,
/// OS/app/rule/parser/model/prompt versions, non-reversible origin fingerprint,
/// and correlation ID.
///
/// Blacklist: any key or value that contains endpoint URL/host, path, file
/// name, content, value, context, body, request, response, header, token,
/// secret, password, cookie, authorization, SQL/parameter, manifest payload,
/// review reason, or stack message.
/// </summary>
public sealed class DiagnosticFieldPolicy
{
    private static readonly HashSet<string> Allowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Core identifiers
        "code", "utc", "scan_id", "stage", "reason_code", "reason",
        "status_code", "correlation_id",

        // Numeric fields
        "count", "duration_ms", "retry_after_seconds",

        // Source
        "module", "method",

        // Version fields
        "os_version", "app_version", "build_version",
        "rule_version", "parser_version", "model_version",
        "prompt_version", "schema_version", "config_schema_version",

        // Fingerprints
        "endpoint_fingerprint", "model_fingerprint",
        "rule_fingerprint", "parser_fingerprint", "prompt_fingerprint",

        // Health-specific
        "is_healthy", "detail_code", "worker_build_hash",
        "sandbox_profile_sid", "error_code",
    };

    private static readonly Regex[] BlacklistPatterns = BuildBlacklistPatterns();

    private static readonly Regex CanaryPattern = new(
        @"CANARY_DIAGNOSTIC_LEAK_|PHANTOM_SECRET_|TEST_EXFIL_TOKEN_|CANARY_SENSITIVE_VALUE_|REDACTED_CANARY_MARKER_",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Returns <c>true</c> when the field key is on the allowlist.
    /// </summary>
    public static bool IsFieldAllowed(string fieldKey)
    {
        if (string.IsNullOrWhiteSpace(fieldKey)) return false;

        if (Allowlist.Contains(fieldKey)) return true;

        // Also check for blacklisted substrings
        foreach (Regex pattern in BlacklistPatterns)
        {
            if (pattern.IsMatch(fieldKey)) return false;
        }

        return false;
    }

    /// <summary>
    /// Returns <c>true</c> when the string value does not contain
    /// blacklisted terms or canary markers.
    /// </summary>
    public static bool IsFieldValueSafe(string fieldKey, string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;

        // Canary check first (fast-fail)
        if (CanaryPattern.IsMatch(value)) return false;

        // Check for "WorkerPayload" or similar ToString leakage
        if (value.Contains("WorkerPayload", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("WorkerJobResult", StringComparison.OrdinalIgnoreCase))
            return false;

        foreach (Regex pattern in BlacklistPatterns)
        {
            if (pattern.IsMatch(value)) return false;
        }

        return true;
    }

    /// <summary>
    /// Returns a <see cref="DiagnosticFieldPolicy"/> describing whether every
    /// field key that appears in the event object graph is allowlisted and
    /// whether any string value trips the blacklist.
    /// </summary>
    public static PolicyValidationResult ValidateEvent(Application.Diagnostics.DiagnosticEvent evt)
    {
        var violations = new List<string>();

        // Check code is a defined enum value
        if (!Enum.IsDefined(evt.Code))
        {
            violations.Add($"Undefined diagnostic code: {(int)evt.Code:X4}");
        }

        // Validate each field in DiagnosticFields
        var fields = evt.Fields;
        foreach (var prop in typeof(Application.Diagnostics.DiagnosticFields).GetProperties())
        {
            string key = ToSnakeCase(prop.Name);
            object? value = prop.GetValue(fields);

            if (value is null) continue;

            if (!IsFieldAllowed(key))
            {
                violations.Add($"Field key not allowed: {key}");
                continue;
            }

            if (value is string s && !IsFieldValueSafe(key, s))
            {
                violations.Add($"Field value unsafe for key: {key}");
            }
        }

        return new PolicyValidationResult(violations.Count == 0, violations);
    }

    /// <summary>
    /// Scans raw bytes for registered canary strings.
    /// Returns a set of matched canaries.
    /// </summary>
    public static IReadOnlySet<string> ScanForCanaries(ReadOnlySpan<byte> bytes, IReadOnlySet<string> canaries)
    {
        var hits = new HashSet<string>(StringComparer.Ordinal);

        // Fast path: check canary pattern first
        string text;
        try
        {
            text = System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return hits;
        }

        if (!CanaryPattern.IsMatch(text)) return hits;

        foreach (string canary in canaries)
        {
            if (text.Contains(canary, StringComparison.Ordinal))
            {
                hits.Add(canary);
            }
        }

        return hits;
    }

    private static Regex[] BuildBlacklistPatterns()
    {
        string[] terms = [
            "url", "host", @"\bpath\b", "file_name", @"\bcontent\b",
            @"\bvalue\b", @"\bcontext\b", @"\bbody\b", @"\brequest\b",
            @"\bresponse\b", @"\bheader\b", @"\btoken\b", @"\bsecret\b",
            @"\bpassword\b", @"\bcookie\b", @"\bauthorization\b",
            @"\bsql\b", @"\bparameter\b", @"\bmanifest\b", @"\bpayload\b",
            "review_reason", "stack_message",
            "command_line", @"\benvironment\b", @"\bcredential\b",
            "private_key", "api_key", "access_key",
            @"\bselect\b", @"\binsert\b", @"\bupdate\b", @"\bdelete\b",
        ];

        return terms
            .Select(t => new Regex(t, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant))
            .ToArray();
    }

    private static string ToSnakeCase(string pascalCase)
    {
        string withAcronymBoundary = Regex.Replace(pascalCase, "([A-Z]+)([A-Z][a-z])", "$1_$2");
        return Regex.Replace(withAcronymBoundary, "([a-z0-9])([A-Z])", "$1_$2")
            .ToLowerInvariant();
    }
}

/// <summary>
/// Result of validating a diagnostic event's fields against the policy.
/// </summary>
public readonly record struct PolicyValidationResult(bool IsValid, IReadOnlyList<string> Violations);
