using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Bounded, pre-redacted input to a single semantic-review LLM call.
/// Carries one target candidate plus the deterministic detector's
/// already-known secret spans. The candidate value, the full context,
/// and the absolute path of the source asset are *not* present in the
/// rendered request — the minimizer replaces them with bounded,
/// masked, path-stripped fields.
///
/// Char offsets in <see cref="DeterministicSecrets"/> are absolute
/// offsets into <see cref="FullContext"/> (UTF-16 code units). Zero or
/// negative offsets, and offsets past the end of the context, are
/// skipped by the minimizer.
/// </summary>
public sealed record SemanticReviewRequest(
    CandidateId CandidateId,
    CategoryId CategoryHint,
    string ContentKind,
    string Extension,
    string VirtualPath,
    string FullContext,
    string CandidateValue,
    SourceLocator CandidateLocator,
    IReadOnlyList<DeterministicSecretSpan> DeterministicSecrets,
    ScanId? ScanId = null,
    string? RulePackHash = null,
    string? AdapterVersion = null);

/// <summary>
/// A span identified by a deterministic detector as containing a known
/// category of secret. Char offsets are absolute positions inside the
/// matching <see cref="SemanticReviewRequest.FullContext"/>. The
/// minimizer coalesces overlapping spans so the original secret bytes
/// never reappear in the rendered output.
/// </summary>
public readonly record struct DeterministicSecretSpan(
    int Start,
    int Length,
    string Category);
