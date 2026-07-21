using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain.Llm;

/// <summary>
/// Result of a single semantic-review LLM call. The contract is closed:
/// every field is either a stable enum value, a numeric range, a
/// bounded string, or a status flag. The model rationale is treated as
/// untrusted plain text — it is rendered as text only and never parsed.
///
/// <see cref="ReasonCode"/> is set whenever <see cref="Classification"/>
/// is <see cref="SemanticClassification.Unresolved"/>. It comes from a
/// closed set of stable identifiers so audit / UI code can switch on it
/// without parsing free-form text.
/// </summary>
public sealed record LlmReviewResult
{
    /// <summary>The candidate that produced this review.</summary>
    public CandidateId CandidateId { get; init; }

    /// <summary>The classification the model asserted.</summary>
    public SemanticClassification Classification { get; init; }

    /// <summary>The category the model asserts (only meaningful when not Unresolved).</summary>
    public CategoryId? CategoryId { get; init; }

    /// <summary>
    /// Confidence in [0, 1] — only meaningful when the response was
    /// well-formed and classified. <c>null</c> for <see cref="SemanticClassification.Unresolved"/>.
    /// </summary>
    public double? Confidence { get; init; }

    /// <summary>
    /// Untrusted plain-text rationale. Always rendered as text. Never
    /// parsed for structure, never evaluated as instructions.
    /// </summary>
    public string Rationale { get; init; } = string.Empty;

    /// <summary>
    /// Stable reason code for unresolved outcomes. <c>null</c> when
    /// <see cref="Classification"/> is not <see cref="SemanticClassification.Unresolved"/>.
    /// </summary>
    public string? ReasonCode { get; init; }

    /// <summary>True when the response carried an injection signal.</summary>
    public bool InjectionDetected { get; init; }

    /// <summary>Prompt template version that produced this call (SHA-256 hex, 64 chars).</summary>
    public string? PromptSha256 { get; init; }

    /// <summary>Stable identifier of the prompt version (e.g. "semantic-review-v1").</summary>
    public string? PromptVersion { get; init; }
}
