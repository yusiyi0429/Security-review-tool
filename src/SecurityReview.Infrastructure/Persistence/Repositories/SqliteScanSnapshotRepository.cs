using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteScanSnapshotRepository : IScanSnapshotRepository
{
    private readonly ISqliteConnectionFactory _factory;

    private const string Table = "scan_config_snapshots";
    private const string Field = "encrypted_payload";

    public SqliteScanSnapshotRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task InsertAsync(ScanId scanId, ScanSnapshotRecord record, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_config_snapshots (scan_id, captured_at_utc, config_hash,
                active_rule_pack_hash, policy_sha256, llm_endpoint_fingerprint,
                llm_model_fingerprint, client_version, parser_adapter_version,
                detector_adapter_version, prompt_version, sandbox_worker_sha256,
                encrypted_payload)
            VALUES (@scanId, @capturedAt, @hash, @rulePackHash, @policySha256,
                @endpointFp, @modelFp, @clientVer, @parserVer, @detectorVer,
                @promptVer, @sandboxWorker, @encrypted);
            """;
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());
        cmd.Parameters.AddWithValue("@capturedAt", record.CapturedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@hash", record.ConfigHash);
        cmd.Parameters.AddWithValue("@rulePackHash", record.ActiveRulePackHash);
        cmd.Parameters.AddWithValue("@policySha256", record.PolicySha256);
        cmd.Parameters.AddWithValue("@endpointFp", record.LlmEndpointFingerprint);
        cmd.Parameters.AddWithValue("@modelFp", record.LlmModelFingerprint);
        cmd.Parameters.AddWithValue("@clientVer", record.ClientVersion);
        cmd.Parameters.AddWithValue("@parserVer", record.ParserAdapterVersion);
        cmd.Parameters.AddWithValue("@detectorVer", record.DetectorAdapterVersion);
        cmd.Parameters.AddWithValue("@promptVer", record.PromptVersion);
        cmd.Parameters.AddWithValue("@sandboxWorker", record.SandboxWorkerSha256);
        cmd.Parameters.Add("@encrypted", SqliteType.Blob).Value = record.EncryptedPayload;

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ScanSnapshotRecord?> GetByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT scan_id, captured_at_utc, config_hash, active_rule_pack_hash,
                policy_sha256, llm_endpoint_fingerprint, llm_model_fingerprint,
                client_version, parser_adapter_version, detector_adapter_version,
                prompt_version, sandbox_worker_sha256, encrypted_payload
            FROM scan_config_snapshots
            WHERE scan_id = @scanId;
            """;
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        return new ScanSnapshotRecord(
            ScanId: new ScanId(Guid.Parse(reader.GetString(0))),
            CapturedAtUtc: DateTimeOffset.Parse(reader.GetString(1),
                System.Globalization.CultureInfo.InvariantCulture),
            ConfigHash: reader.GetString(2),
            ActiveRulePackHash: reader.GetString(3),
            PolicySha256: reader.GetString(4),
            LlmEndpointFingerprint: reader.GetString(5),
            LlmModelFingerprint: reader.GetString(6),
            ClientVersion: reader.GetString(7),
            ParserAdapterVersion: reader.GetString(8),
            DetectorAdapterVersion: reader.GetString(9),
            PromptVersion: reader.GetString(10),
            SandboxWorkerSha256: reader.GetString(11),
            EncryptedPayload: GetBlobBytes(reader, 12));
    }

    public async Task<string?> GetConfigHashAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT config_hash FROM scan_config_snapshots WHERE scan_id = @scanId;";
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result is string s ? s : null;
    }

    private static byte[] GetBlobBytes(SqliteDataReader reader, int ordinal)
    {
        using var stream = reader.GetStream(ordinal);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(byte[]))]
internal partial class ScanSnapshotJsonContext : JsonSerializerContext;
