using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Persistence for the semantic-review audit trail. One row per
/// attempt captures only metadata — endpoint fingerprint, model
/// fingerprint, prompt SHA-256, status code, duration, and reason
/// code. The request body, response body, candidate value, and
/// context are never persisted in any plain column.
/// </summary>
public interface ILlmAttemptRepository
{
    /// <summary>
    /// Record one HTTP attempt. The supplied
    /// <see cref="LlmAttemptPersistenceRecord"/> carries no body /
    /// header material; only fingerprints, timestamps, status code,
    /// duration, and reason code.
    /// </summary>
    Task PersistAttemptAsync(LlmAttemptPersistenceRecord record, CancellationToken cancellationToken);

    /// <summary>
    /// Record the final outcome of one semantic review. Used by the
    /// queue when it persists a Confirmed / Possible / Unlikely
    /// classification. The body / header / context are never
    /// persisted in plain columns.
    /// </summary>
    Task PersistReviewAsync(PersistedLlmReview review, CancellationToken cancellationToken);

    /// <summary>
    /// Returns every persisted attempt row, used by canary tests to
    /// verify the database carries no plain column canary. The result
    /// is intentionally unordered — tests should not depend on
    /// insertion order.
    /// </summary>
    Task<IReadOnlyList<LlmAttemptLogEntry>> ReadAllAttemptsAsync(CancellationToken cancellationToken);
}

/// <summary>
/// One HTTP attempt's metadata. No body, no header, no candidate
/// value, no context, no endpoint host, and no model identifier
/// appear in any field.
/// </summary>
public sealed record LlmAttemptPersistenceRecord(
    LlmReviewResult Result,
    int AttemptNumber,
    string CacheKey,
    string RulePackHash,
    string AdapterVersion,
    string EndpointFingerprint,
    string ModelFingerprint,
    DateTimeOffset StartedAtUtc,
    TimeSpan Duration,
    int StatusCodeOrZero);

/// <summary>
/// Read-side projection of a persisted attempt row. Carries exactly
/// the plain columns the database stores; the canary scan reads
/// every one to assert no endpoint / model / candidate / context /
/// token value leaked to disk.
/// </summary>
public sealed record LlmAttemptLogEntry(
    string AttemptId,
    string ReviewId,
    string ScanId,
    string CandidateId,
    int AttemptNumber,
    int? StatusCode,
    long DurationMs,
    string ReasonCode,
    string EndpointFingerprint,
    string ModelFingerprint,
    string PromptSha256,
    string PromptVersion,
    string CacheKey,
    string RulePackHash,
    string AdapterVersion,
    DateTimeOffset StartedAtUtc)
{
    /// <summary>
    /// Closed enumeration of (column name, value) pairs that exist
    /// as plain text columns in the database. The canary scan
    /// iterates this projection to look for forbidden tokens.
    /// </summary>
    public IEnumerable<(string Column, string Value)> PlainColumns
    {
        get
        {
            yield return ("attempt_id", AttemptId);
            yield return ("review_id", ReviewId);
            yield return ("scan_id", ScanId);
            yield return ("candidate_id", CandidateId);
            yield return ("status_code", StatusCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
            yield return ("duration_ms", DurationMs.ToString(System.Globalization.CultureInfo.InvariantCulture));
            yield return ("reason_code", ReasonCode);
            yield return ("endpoint_fingerprint", EndpointFingerprint);
            yield return ("model_fingerprint", ModelFingerprint);
            yield return ("prompt_sha256", PromptSha256);
            yield return ("prompt_version", PromptVersion);
            yield return ("cache_key", CacheKey);
            yield return ("rule_pack_hash", RulePackHash);
            yield return ("adapter_version", AdapterVersion);
            yield return ("started_at_utc", StartedAtUtc.ToString("O"));
        }
    }
}
