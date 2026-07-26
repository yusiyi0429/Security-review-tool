using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteScanCreationRepository : IScanCreationRepository
{
    private const string ScanTable = "scan_runs";
    private const string ScanField = "encrypted_payload";

    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;

    public SqliteScanCreationRepository(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
    }

    public async Task InsertAsync(
        ScanRun scan,
        ScanSnapshotRecord snapshot,
        CancellationToken cancellationToken = default)
    {
        if (scan.ScanId != snapshot.ScanId)
        {
            throw new ArgumentException(
                "Scan and snapshot identifiers must match.",
                nameof(snapshot));
        }

        byte[] payload = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(
                new ScanRunPayload(Description: null),
                ScanRunJsonContext.Default.ScanRunPayload));
        EncryptedPayload encrypted = _protector.Protect(
            ScanTable,
            scan.ScanId.Value.ToString(),
            ScanField,
            payload);
        byte[] encryptedJson = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(
                encrypted,
                ScanRunJsonContext.Default.EncryptedPayload));

        await using SqliteConnection connection = await _factory
            .OpenAsync(cancellationToken)
            .ConfigureAwait(false);
        await using SqliteTransaction transaction = connection.BeginTransaction();
        try
        {
            await InsertScanAsync(
                connection,
                transaction,
                scan,
                encryptedJson,
                cancellationToken)
                .ConfigureAwait(false);
            await InsertSnapshotAsync(
                connection,
                transaction,
                snapshot,
                cancellationToken)
                .ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task InsertScanAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScanRun scan,
        byte[] encryptedPayload,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO scan_runs (scan_id, status, created_at_utc, updated_at_utc,
                rule_pack_hash, client_version, pipeline_fingerprint, planned_units,
                version, encrypted_payload)
            VALUES (@scanId, @status, @createdAt, @updatedAt, @rulePackHash,
                @clientVersion, @pipelineFingerprint, @plannedUnits, @version,
                @encryptedPayload);
            """;
        command.Parameters.AddWithValue("@scanId", scan.ScanId.Value.ToString());
        command.Parameters.AddWithValue("@status", (int)scan.Status);
        command.Parameters.AddWithValue("@createdAt", scan.CreatedAtUtc.ToString("O"));
        command.Parameters.AddWithValue("@updatedAt", scan.UpdatedAtUtc.ToString("O"));
        command.Parameters.AddWithValue("@rulePackHash", scan.RuleFingerprint);
        command.Parameters.AddWithValue("@clientVersion", scan.ClientFingerprint);
        command.Parameters.AddWithValue(
            "@pipelineFingerprint",
            scan.PipelineFingerprint);
        command.Parameters.AddWithValue("@plannedUnits", scan.PlannedCount);
        command.Parameters.AddWithValue("@version", scan.Version);
        command.Parameters.AddWithValue("@encryptedPayload", encryptedPayload);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertSnapshotAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ScanSnapshotRecord snapshot,
        CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO scan_config_snapshots (scan_id, captured_at_utc, config_hash,
                active_rule_pack_hash, policy_sha256, llm_endpoint_fingerprint,
                llm_model_fingerprint, client_version, parser_adapter_version,
                detector_adapter_version, prompt_version, sandbox_worker_sha256,
                encrypted_payload)
            VALUES (@scanId, @capturedAt, @hash, @rulePackHash, @policySha256,
                @endpointFp, @modelFp, @clientVer, @parserVer, @detectorVer,
                @promptVer, @sandboxWorker, @encrypted);
            """;
        command.Parameters.AddWithValue(
            "@scanId",
            snapshot.ScanId.Value.ToString());
        command.Parameters.AddWithValue(
            "@capturedAt",
            snapshot.CapturedAtUtc.ToString("O"));
        command.Parameters.AddWithValue("@hash", snapshot.ConfigHash);
        command.Parameters.AddWithValue(
            "@rulePackHash",
            snapshot.ActiveRulePackHash);
        command.Parameters.AddWithValue("@policySha256", snapshot.PolicySha256);
        command.Parameters.AddWithValue(
            "@endpointFp",
            snapshot.LlmEndpointFingerprint);
        command.Parameters.AddWithValue(
            "@modelFp",
            snapshot.LlmModelFingerprint);
        command.Parameters.AddWithValue("@clientVer", snapshot.ClientVersion);
        command.Parameters.AddWithValue(
            "@parserVer",
            snapshot.ParserAdapterVersion);
        command.Parameters.AddWithValue(
            "@detectorVer",
            snapshot.DetectorAdapterVersion);
        command.Parameters.AddWithValue("@promptVer", snapshot.PromptVersion);
        command.Parameters.AddWithValue(
            "@sandboxWorker",
            snapshot.SandboxWorkerSha256);
        command.Parameters.Add("@encrypted", SqliteType.Blob).Value =
            snapshot.EncryptedPayload;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
