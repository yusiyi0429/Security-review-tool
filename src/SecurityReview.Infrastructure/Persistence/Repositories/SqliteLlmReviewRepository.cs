using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

/// <summary>
/// SQLite-backed persistence for the semantic-review audit trail.
/// Two tables are written:
///   * <c>llm_reviews</c> — one row per completed review (encrypted
///     rationale / reason payload). Schema v1.
///   * <c>llm_review_attempts</c> — one row per HTTP attempt with
///     only fingerprints, status code, duration, and reason code.
///     Schema v2.
///
/// The repository never writes the request body, the response body,
/// the candidate value, the candidate context, the endpoint host, or
/// the model identifier. Only fingerprints and opaque ids appear in
/// plain columns.
/// </summary>
public sealed class SqliteLlmReviewRepository : ILlmAttemptRepository, ISemanticReviewPersister
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;

    private const string ReviewTable = "llm_reviews";
    private const string AttemptTable = "llm_review_attempts";
    private const string ReviewField = "encrypted_payload";

    public SqliteLlmReviewRepository(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(protector);
        _factory = factory;
        _protector = protector;
    }

    public async Task PersistAttemptAsync(
        LlmAttemptPersistenceRecord record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO llm_review_attempts
                (attempt_id, review_id, scan_id, candidate_id, attempt_number,
                 status_code, duration_ms, reason_code, endpoint_fingerprint,
                 model_fingerprint, prompt_sha256, prompt_version, cache_key,
                 rule_pack_hash, adapter_version, started_at_utc)
            VALUES
                (@attemptId, @reviewId, @scanId, @candidateId, @attemptNumber,
                 @statusCode, @durationMs, @reasonCode, @endpointFingerprint,
                 @modelFingerprint, @promptSha256, @promptVersion, @cacheKey,
                 @rulePackHash, @adapterVersion, @startedAtUtc);
            """;

        string attemptId = Guid.NewGuid().ToString("D");
        string reviewId = Guid.NewGuid().ToString("D");
        long durationMs = (long)record.Duration.TotalMilliseconds;
        if (durationMs < 0) durationMs = 0;

        cmd.Parameters.AddWithValue("@attemptId", attemptId);
        cmd.Parameters.AddWithValue("@reviewId", reviewId);
        cmd.Parameters.AddWithValue("@scanId", string.Empty);
        cmd.Parameters.AddWithValue("@candidateId", record.Result.CandidateId.Value.ToString("D"));
        cmd.Parameters.AddWithValue("@attemptNumber", record.AttemptNumber);
        cmd.Parameters.AddWithValue("@statusCode",
            record.StatusCodeOrZero == 0
                ? (object)DBNull.Value
                : record.StatusCodeOrZero);
        cmd.Parameters.AddWithValue("@durationMs", durationMs);
        cmd.Parameters.AddWithValue("@reasonCode", MapReasonCode(record.Result));
        cmd.Parameters.AddWithValue("@endpointFingerprint", record.EndpointFingerprint ?? string.Empty);
        cmd.Parameters.AddWithValue("@modelFingerprint", record.ModelFingerprint ?? string.Empty);
        cmd.Parameters.AddWithValue("@promptSha256", record.Result.PromptSha256 ?? string.Empty);
        cmd.Parameters.AddWithValue("@promptVersion", record.Result.PromptVersion ?? OpenAiChatRequest.PromptVersion);
        cmd.Parameters.AddWithValue("@cacheKey", record.CacheKey ?? string.Empty);
        cmd.Parameters.AddWithValue("@rulePackHash", record.RulePackHash ?? string.Empty);
        cmd.Parameters.AddWithValue("@adapterVersion", record.AdapterVersion ?? string.Empty);
        cmd.Parameters.AddWithValue("@startedAtUtc", record.StartedAtUtc.ToString("O"));

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task PersistReviewAsync(PersistedLlmReview review, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(review);

        byte[] payload = SerializeReviewPayload(review);
        byte[] encryptedPayload = SerializeEncryptedPayload(
            _protector.Protect(ReviewTable, review.CandidateId.Value.ToString("D"), ReviewField, payload));

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO llm_reviews
                (review_id, scan_id, candidate_id, cache_key, status,
                 endpoint_fingerprint, model_id, prompt_version,
                 attempted_at_utc, encrypted_payload)
            VALUES
                (@reviewId, @scanId, @candidateId, @cacheKey, @status,
                 @endpointFingerprint, @modelId, @promptVersion,
                 @attemptedAtUtc, @encryptedPayload);
            """;

        cmd.Parameters.AddWithValue("@reviewId", Guid.NewGuid().ToString("D"));
        cmd.Parameters.AddWithValue("@scanId", review.ScanId.Value.ToString("D"));
        cmd.Parameters.AddWithValue("@candidateId", review.CandidateId.Value.ToString("D"));
        cmd.Parameters.AddWithValue("@cacheKey", review.CacheKey ?? string.Empty);
        cmd.Parameters.AddWithValue("@status", (int)review.Classification);
        cmd.Parameters.AddWithValue("@endpointFingerprint", review.EndpointFingerprint ?? string.Empty);
        cmd.Parameters.AddWithValue("@modelId", review.ModelFingerprint ?? string.Empty);
        cmd.Parameters.AddWithValue("@promptVersion", review.PromptVersion ?? OpenAiChatRequest.PromptVersion);
        cmd.Parameters.AddWithValue("@attemptedAtUtc", review.AttemptedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@encryptedPayload", encryptedPayload);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    Task ISemanticReviewPersister.PersistAsync(PersistedLlmReview review, CancellationToken cancellationToken)
        => PersistReviewAsync(review, cancellationToken);

    public async Task<IReadOnlyList<LlmAttemptLogEntry>> ReadAllAttemptsAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT attempt_id, review_id, scan_id, candidate_id, attempt_number,
                   status_code, duration_ms, reason_code, endpoint_fingerprint,
                   model_fingerprint, prompt_sha256, prompt_version, cache_key,
                   rule_pack_hash, adapter_version, started_at_utc
            FROM llm_review_attempts;
            """;

        var entries = new List<LlmAttemptLogEntry>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            entries.Add(new LlmAttemptLogEntry(
                AttemptId: reader.GetString(0),
                ReviewId: reader.GetString(1),
                ScanId: reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                CandidateId: reader.GetString(3),
                AttemptNumber: reader.GetInt32(4),
                StatusCode: reader.IsDBNull(5) ? null : reader.GetInt32(5),
                DurationMs: reader.GetInt64(6),
                ReasonCode: reader.GetString(7),
                EndpointFingerprint: reader.IsDBNull(8) ? string.Empty : reader.GetString(8),
                ModelFingerprint: reader.IsDBNull(9) ? string.Empty : reader.GetString(9),
                PromptSha256: reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                PromptVersion: reader.IsDBNull(11) ? string.Empty : reader.GetString(11),
                CacheKey: reader.IsDBNull(12) ? string.Empty : reader.GetString(12),
                RulePackHash: reader.IsDBNull(13) ? string.Empty : reader.GetString(13),
                AdapterVersion: reader.IsDBNull(14) ? string.Empty : reader.GetString(14),
                StartedAtUtc: DateTimeOffset.Parse(
                    reader.GetString(15),
                    System.Globalization.CultureInfo.InvariantCulture)));
        }
        return entries;
    }

    private static byte[] SerializeReviewPayload(PersistedLlmReview review)
    {
        var payload = new ReviewPayload(
            Classification: (int)review.Classification,
            CategoryId: review.CategoryId,
            Confidence: review.Confidence,
            ReasonCode: review.ReasonCode,
            InjectionDetected: review.InjectionDetected,
            PromptSha256: review.PromptSha256,
            PromptVersion: review.PromptVersion);
        return System.Text.Encoding.UTF8.GetBytes(
            System.Text.Json.JsonSerializer.Serialize(payload, LlmReviewJsonContext.Default.ReviewPayload));
    }

    private static byte[] SerializeEncryptedPayload(EncryptedPayload envelope)
    {
        return System.Text.Encoding.UTF8.GetBytes(
            System.Text.Json.JsonSerializer.Serialize(envelope, LlmReviewJsonContext.Default.EncryptedPayload));
    }

    private static string MapReasonCode(LlmReviewResult result)
    {
        if (result.InjectionDetected)
            return "injection_detected";
        if (result.Classification == SemanticClassification.Unresolved)
            return result.ReasonCode ?? "unresolved";
        return "success";
    }

    internal sealed record ReviewPayload(
        int Classification,
        string CategoryId,
        double? Confidence,
        string ReasonCode,
        bool InjectionDetected,
        string PromptSha256,
        string PromptVersion);
}

[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
[System.Text.Json.Serialization.JsonSerializable(typeof(SqliteLlmReviewRepository.ReviewPayload))]
[System.Text.Json.Serialization.JsonSerializable(typeof(EncryptedPayload))]
internal sealed partial class LlmReviewJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
