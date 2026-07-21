using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Llm;

/// <summary>
/// Closed set of classifications the LLM may return for a single candidate.
/// The set is intentionally small so audit / UI code can switch on it
/// without parsing free-form strings. <see cref="Unresolved"/> is the
/// fallback returned whenever the response shape, content, or injection
/// signals are not trustworthy; UI code must render it with an
/// accompanying <c>ReasonCode</c> and never trust any rationale that
/// came from the model itself.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SemanticClassification>))]
public enum SemanticClassification
{
    /// <summary>Model asserts the candidate is genuinely sensitive.</summary>
    Confirmed = 0,

    /// <summary>Model says the candidate looks sensitive but wants human review.</summary>
    Possible = 1,

    /// <summary>
    /// Model says the candidate is benign. This is *not* a delete signal —
    /// the value is still kept on the finding for audit; only the UI /
    /// conclusion calculator downgrades it.
    /// </summary>
    Unlikely = 2,

    /// <summary>
    /// Response was malformed, refused, truncated, or carried an injection
    /// signal. The caller MUST treat the model output as untrusted and
    /// surface a stable <c>ReasonCode</c> to the operator.
    /// </summary>
    Unresolved = 3,
}
