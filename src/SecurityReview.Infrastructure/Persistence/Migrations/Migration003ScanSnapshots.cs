using Microsoft.Data.Sqlite;

namespace SecurityReview.Infrastructure.Persistence.Migrations;

/// <summary>
/// Schema version 3: stores the immutable preflight
/// <see cref="SecurityReview.Application.Scans.ScanConfigurationSnapshot"/>
/// for every scan run so the diff service and audit trail can prove what
/// the scan decided even after the user mutates the UI inputs.
///
/// Only fingerprints and enum/identifier columns appear in plain text;
/// the rest of the snapshot lives in <c>encrypted_payload</c>.
/// </summary>
public sealed class Migration003ScanSnapshots : IMigration
{
    public int Version => 3;

    public async Task ApplyAsync(SqliteConnection connection, string clientBuild, CancellationToken cancellationToken = default)
    {
        await using var cmd = connection.CreateCommand();

        // ---------------------------------------------------------------
        // scan_config_snapshots — one row per scan run, immutable
        // ---------------------------------------------------------------
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_config_snapshots (
                scan_id                  TEXT PRIMARY KEY,
                captured_at_utc          TEXT NOT NULL,
                config_hash              TEXT NOT NULL,
                active_rule_pack_hash    TEXT NOT NULL,
                policy_sha256            TEXT NOT NULL,
                llm_endpoint_fingerprint TEXT NOT NULL,
                llm_model_fingerprint    TEXT NOT NULL,
                client_version           TEXT NOT NULL,
                parser_adapter_version   TEXT NOT NULL,
                detector_adapter_version TEXT NOT NULL,
                prompt_version           TEXT NOT NULL,
                sandbox_worker_sha256    TEXT NOT NULL,
                encrypted_payload        BLOB NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id),
                CHECK (length(scan_id) = 36)
            );
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        cmd.CommandText = """
            CREATE INDEX IF NOT EXISTS ix_scan_config_snapshots_hash
                ON scan_config_snapshots(config_hash);
            CREATE INDEX IF NOT EXISTS ix_scan_config_snapshots_rule_pack
                ON scan_config_snapshots(active_rule_pack_hash);
            """;
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Record schema version.
        cmd.CommandText = """
            INSERT INTO schema_versions (version, applied_at_utc, client_build)
            VALUES (3, @applied, @build);
            """;
        cmd.Parameters.AddWithValue("@applied", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@build", clientBuild);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
