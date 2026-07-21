namespace SecurityReview.Application.Diagnostics;

/// <summary>
/// Closed set of fields that may appear in a <see cref="DiagnosticEvent"/>.
/// Every field has a stable, non-PII meaning. The set is intentionally
/// restrictive: arbitrary dictionaries, raw request bodies, response
/// bodies, endpoint URLs, hosts, credential material, and exception
/// messages never enter a diagnostic event.
/// </summary>
public sealed record DiagnosticFields
{
    /// <summary>Stage that emitted the event (e.g. "llm.connection_test").</summary>
    public string? Stage { get; init; }

    /// <summary>Machine-readable reason code (stable string within the stage).</summary>
    public string? ReasonCode { get; init; }

    /// <summary>HTTP / transport status code (e.g. 200, 401, 403, 500, 0 for none).</summary>
    public int? StatusCode { get; init; }

    /// <summary>Upstream retry-after hint in seconds (only when the server set one).</summary>
    public int? RetryAfterSeconds { get; init; }

    /// <summary>Count of items considered (e.g. number of candidates).</summary>
    public long? Count { get; init; }

    /// <summary>Duration in milliseconds, when relevant.</summary>
    public long? DurationMs { get; init; }

    /// <summary>Module that produced the event (e.g. "Infrastructure.Llm").</summary>
    public string? Module { get; init; }

    /// <summary>Method that produced the event (no parameters).</summary>
    public string? Method { get; init; }

    /// <summary>Schema version of the event payload (e.g. 1).</summary>
    public int? SchemaVersion { get; init; }

    /// <summary>Module/build version (e.g. "1.2.3").</summary>
    public string? BuildVersion { get; init; }

    /// <summary>Configuration schema version (e.g. 1).</summary>
    public int? ConfigSchemaVersion { get; init; }

    /// <summary>Origin fingerprint (16-hex) — never the full URL/host.</summary>
    public string? EndpointFingerprint { get; init; }

    /// <summary>Model fingerprint (16-hex) — never the model identifier.</summary>
    public string? ModelFingerprint { get; init; }

    /// <summary>Rule fingerprint (16-hex) — never the rule identifier.</summary>
    public string? RuleFingerprint { get; init; }

    /// <summary>Parser fingerprint (16-hex) — never the parser name.</summary>
    public string? ParserFingerprint { get; init; }

    /// <summary>Prompt template fingerprint (16-hex) — never the prompt text.</summary>
    public string? PromptFingerprint { get; init; }
}