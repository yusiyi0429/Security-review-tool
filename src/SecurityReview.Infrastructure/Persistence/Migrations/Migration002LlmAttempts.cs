using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// Schema version 2: adds the <c>llm_review_attempts</c> table that
/// holds one row per HTTP attempt so the audit layer can answer
/// "when did this candidate last time out?", "how many 5xx did this
/// endpoint fingerprint emit during the scan?", and similar questions
/// without ever exposing the request body, response body, or any
/// plain column that could carry an endpoint host, model identifier,
/// candidate value, context snippet, or API key.
///
/// All sensitive value columns are named <c>encrypted_payload</c>
/// — this migration adds none; the table is fingerprint-only.
/// </summary>
public sealed class Migration002LlmAttempts : IMigration
{
    public int Version => 2;

    public async Task ApplyAsync(SqliteConnection connection, string clientBuild, CancellationToken cancellationToken = default)
    {
        await using var cmd = connection.CreateCommand();

        // ---------------------------------------------------------------
        // 1. llm_review_attempts — one row per HTTP attempt
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS llm_review_attempts (
                attempt_id            TEXT PRIMARY KEY,
                review_id             TEXT NOT NULL,
                scan_id               TEXT NOT NULL,
                candidate_id          TEXT NOT NULL,
                attempt_number        INTEGER NOT NULL,
                status_code           INTEGER,
                duration_ms           INTEGER NOT NULL,
                reason_code           TEXT NOT NULL,
                endpoint_fingerprint  TEXT,
                model_fingerprint     TEXT,
                prompt_sha256         TEXT,
                prompt_version        TEXT,
                cache_key             TEXT,
                rule_pack_hash        TEXT,
                adapter_version       TEXT,
                started_at_utc        TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(attempt_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // Indexes
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_llm_review_attempts_review
                ON llm_review_attempts(review_id);
            CREATE INDEX IF NOT EXISTS ix_llm_review_attempts_candidate
                ON llm_review_attempts(candidate_id);
            CREATE INDEX IF NOT EXISTS ix_llm_review_attempts_scan_started
                ON llm_review_attempts(scan_id, started_at_utc);
            CREATE INDEX IF NOT EXISTS ix_llm_review_attempts_endpoint
                ON llm_review_attempts(endpoint_fingerprint);
            CREATE INDEX IF NOT EXISTS ix_llm_review_attempts_reason
                ON llm_review_attempts(reason_code);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Record schema version.
        cmd.CommandText = """
            INSERT INTO schema_versions (version, applied_at_utc, client_build)
            VALUES (2, @applied, @build);
            """;
        cmd.Parameters.AddWithValue("@applied", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@build", clientBuild);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
