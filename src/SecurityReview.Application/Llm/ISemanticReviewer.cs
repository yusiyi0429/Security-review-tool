using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Semantic-review service contract. The reviewer renders a
/// <see cref="SemanticReviewRequest"/> into a bounded prompt, sends it
/// to the configured intranet LLM, and validates the response through
/// a closed parser. The implementation must never expose the model
/// rationale as instructions — it is plain text rendered into the UI
/// verbatim.
///
/// All <see cref="LlmReviewResult"/> instances returned from this
/// interface have already been validated; the caller may trust the
/// <see cref="LlmReviewResult.Classification"/> and
/// <see cref="LlmReviewResult.ReasonCode"/> values without further
/// checks.
/// </summary>
public interface ISemanticReviewer
{
    /// <summary>
    /// Build, send, parse, and return one bounded semantic review.
    /// The call is synchronous from the caller's perspective: it may
    /// internally fan out per-candidate work but always returns a
    /// single, validated result.
    /// </summary>
    /// <exception cref="OperationCanceledException">
    /// Thrown when the supplied <paramref name="cancellationToken"/>
    /// is cancelled.
    /// </exception>
    Task<LlmReviewResult> ReviewAsync(
        SemanticReviewRequest request,
        CancellationToken cancellationToken = default);
}
