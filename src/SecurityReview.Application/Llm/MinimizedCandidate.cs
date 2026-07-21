using SecurityReview.Domain;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Result of <see cref="CandidateMinimizer.Minimize"/>. The struct is
/// a sealed record with no behaviour of its own — the minimizer is the
/// single producer.
///
/// <c>PackedUtf8ByteLength</c> is the UTF-8 byte size of the JSON the
/// request builder is about to emit. The caller must reject any
/// request whose packed candidate exceeds the 16 KiB ceiling and
/// treat it as <c>llm_request_contract_oversize</c>.
/// </summary>
public sealed record MinimizedCandidate(
    CandidateId CandidateId,
    CategoryId CategoryHint,
    string ContentKind,
    string Extension,
    string UntrustedContext,
    string RedactedCandidateValue,
    long ContextLeftTruncatedBytes,
    long ContextRightTruncatedBytes,
    long SecretRedactions,
    bool ContextTruncated,
    int PackedUtf8ByteLength);
