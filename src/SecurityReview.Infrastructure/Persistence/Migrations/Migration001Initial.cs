using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// Initial schema version 1: 14 tables with foreign keys, TEXT UUIDs,
/// UTC timestamps, INTEGER enums, and indexes on frequently-queried columns.
/// All sensitive-value columns are named <c>encrypted_payload</c>.
/// </summary>
public sealed class Migration001Initial : IMigration
{
    public int Version => 1;

    public async Task ApplyAsync(SqliteConnection connection, string clientBuild, CancellationToken cancellationToken = default)
    {
        await using var cmd = connection.CreateCommand();

        // ---------------------------------------------------------------
        // 1. schema_versions
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_versions (
                version     INTEGER PRIMARY KEY,
                applied_at_utc TEXT NOT NULL,
                client_build    TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 2. scan_runs
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_runs (
                scan_id             TEXT PRIMARY KEY,
                status              INTEGER NOT NULL,
                created_at_utc      TEXT NOT NULL,
                updated_at_utc      TEXT NOT NULL,
                rule_pack_hash      TEXT NOT NULL,
                client_version      TEXT NOT NULL,
                pipeline_fingerprint TEXT NOT NULL,
                planned_units       INTEGER NOT NULL,
                version             INTEGER NOT NULL DEFAULT 1,
                encrypted_payload   BLOB,
                CHECK (length(scan_id) = 36),
                CHECK (version > 0)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 3. assets
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS assets (
                asset_row_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                manifest_hash   TEXT NOT NULL,
                asset_id_hmac   TEXT NOT NULL,
                encrypted_payload BLOB,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 4. file_records
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS file_records (
                file_id             TEXT PRIMARY KEY,
                scan_id             TEXT NOT NULL,
                path_hmac           TEXT NOT NULL,
                content_sha256      TEXT,
                size                INTEGER,
                format_id           TEXT,
                coverage_status     INTEGER NOT NULL,
                parser_fingerprint  TEXT,
                encrypted_payload   BLOB,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(file_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 5. finding_groups
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS finding_groups (
                group_id            TEXT PRIMARY KEY,
                scan_id             TEXT NOT NULL,
                value_hmac          TEXT NOT NULL,
                category_id         INTEGER NOT NULL,
                severity            INTEGER NOT NULL,
                confidence          INTEGER NOT NULL,
                difference_status   INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(group_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 6. finding_occurrences
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS finding_occurrences (
                occurrence_id               TEXT PRIMARY KEY,
                group_id                    TEXT NOT NULL,
                file_id                     TEXT NOT NULL,
                rule_id                     TEXT NOT NULL,
                detector_id                 TEXT NOT NULL,
                requires_semantic_review    INTEGER NOT NULL DEFAULT 0,
                encrypted_payload           BLOB,
                FOREIGN KEY (group_id) REFERENCES finding_groups(group_id),
                FOREIGN KEY (file_id)  REFERENCES file_records(file_id),
                CHECK (length(occurrence_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 7. coverage_gaps
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS coverage_gaps (
                gap_id           TEXT PRIMARY KEY,
                scan_id          TEXT NOT NULL,
                file_id          TEXT,
                stage            TEXT NOT NULL,
                reason           INTEGER NOT NULL,
                detail_code      TEXT NOT NULL,
                planned_bytes    INTEGER,
                processed_bytes  INTEGER,
                encrypted_payload BLOB,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                FOREIGN KEY (file_id) REFERENCES file_records(file_id),
                CHECK (length(gap_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 8. llm_reviews
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS llm_reviews (
                review_id               TEXT PRIMARY KEY,
                scan_id                 TEXT NOT NULL,
                candidate_id            TEXT NOT NULL,
                cache_key               TEXT NOT NULL,
                status                  INTEGER NOT NULL,
                endpoint_fingerprint    TEXT,
                model_id                TEXT,
                prompt_version          TEXT,
                attempted_at_utc        TEXT,
                encrypted_payload       BLOB,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(review_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 9. review_decisions
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS review_decisions (
                decision_id         TEXT PRIMARY KEY,
                scan_id             TEXT NOT NULL,
                group_id            TEXT,
                occurrence_id       TEXT,
                status              INTEGER NOT NULL,
                user_sid_hmac       TEXT NOT NULL,
                decided_at_utc      TEXT NOT NULL,
                encrypted_payload   BLOB,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                FOREIGN KEY (group_id) REFERENCES finding_groups(group_id),
                FOREIGN KEY (occurrence_id) REFERENCES finding_occurrences(occurrence_id),
                CHECK (length(decision_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 10. exception_grants
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS exception_grants (
                exception_id                TEXT PRIMARY KEY,
                asset_binding_hmac          TEXT NOT NULL,
                occurrence_binding_hmac     TEXT,
                rule_pack_hash              TEXT NOT NULL,
                valid_until_utc             TEXT NOT NULL,
                created_at_utc              TEXT NOT NULL,
                user_sid_hmac               TEXT NOT NULL,
                encrypted_payload           BLOB,
                CHECK (length(exception_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 11. rule_packs
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS rule_packs (
                rule_pack_hash      TEXT PRIMARY KEY,
                rule_pack_id        TEXT NOT NULL,
                version             TEXT NOT NULL,
                signer_id           TEXT NOT NULL,
                imported_at_utc     TEXT NOT NULL,
                status              INTEGER NOT NULL,
                package_path_hmac   TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 12. cache_entries
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS cache_entries (
                cache_key           TEXT PRIMARY KEY,
                stage               TEXT NOT NULL,
                created_at_utc      TEXT NOT NULL,
                last_used_at_utc    TEXT NOT NULL,
                source_scan_id      TEXT,
                encrypted_payload   BLOB
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // 13. diagnostic_events
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS diagnostic_events (
                event_id                TEXT PRIMARY KEY,
                scan_id                 TEXT,
                event_code              TEXT NOT NULL,
                occurred_at_utc         TEXT NOT NULL,
                count_value             INTEGER,
                duration_ms             REAL,
                redacted_fields_json    TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(event_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // ---------------------------------------------------------------
        // Indexes
        // ---------------------------------------------------------------
        // scan_runs
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_scan_runs_status ON scan_runs(status);
            CREATE INDEX IF NOT EXISTS ix_scan_runs_created ON scan_runs(created_at_utc);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // file_records
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_file_records_scan_path ON file_records(scan_id, path_hmac);
            CREATE INDEX IF NOT EXISTS ix_file_records_content_hash ON file_records(content_sha256);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // finding_groups
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_finding_groups_scan_value ON finding_groups(scan_id, value_hmac);
            CREATE INDEX IF NOT EXISTS ix_finding_groups_category ON finding_groups(category_id);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // finding_occurrences
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_finding_occurrences_group ON finding_occurrences(group_id);
            CREATE INDEX IF NOT EXISTS ix_finding_occurrences_file ON finding_occurrences(file_id);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // coverage_gaps
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_coverage_gaps_scan ON coverage_gaps(scan_id);
            CREATE INDEX IF NOT EXISTS ix_coverage_gaps_reason ON coverage_gaps(scan_id, reason);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // llm_reviews
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_llm_reviews_candidate ON llm_reviews(candidate_id);
            CREATE INDEX IF NOT EXISTS ix_llm_reviews_cache_key ON llm_reviews(cache_key);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // review_decisions
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_review_decisions_group ON review_decisions(group_id);
            CREATE INDEX IF NOT EXISTS ix_review_decisions_occurrence ON review_decisions(occurrence_id);
            CREATE INDEX IF NOT EXISTS ix_review_decisions_time ON review_decisions(decided_at_utc);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // exception_grants
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_exception_grants_binding ON exception_grants(asset_binding_hmac);
            CREATE INDEX IF NOT EXISTS ix_exception_grants_expiry ON exception_grants(valid_until_utc);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // cache_entries
        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_cache_entries_stage ON cache_entries(stage);
            CREATE INDEX IF NOT EXISTS ix_cache_entries_last_used ON cache_entries(last_used_at_utc);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Record schema version.
        cmd.CommandText = """
            INSERT INTO schema_versions (version, applied_at_utc, client_build)
            VALUES (1, @applied, @build);
            """;
        cmd.Parameters.AddWithValue("@applied", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@build", clientBuild);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
