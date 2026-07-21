using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteScanRepository : IScanRepository
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;

    private const string Table = "scan_runs";
    private const string Field = "encrypted_payload";

    public SqliteScanRepository(ISqliteConnectionFactory factory, IPayloadProtector protector)
    {
        _factory = factory;
        _protector = protector;
    }

    public async Task InsertAsync(ScanRun scan, CancellationToken cancellationToken = default)
    {
        var payload = new ScanRunPayload(Description: null);
        byte[] jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, ScanRunJsonContext.Default.ScanRunPayload));
        var encrypted = _protector.Protect(Table, scan.ScanId.Value.ToString(), Field, jsonBytes);
        byte[] encryptedJson = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(encrypted, ScanRunJsonContext.Default.EncryptedPayload));

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_runs (scan_id, status, created_at_utc, updated_at_utc,
                rule_pack_hash, client_version, pipeline_fingerprint, planned_units,
                version, encrypted_payload)
            VALUES (@scanId, @status, @createdAt, @updatedAt, @rulePackHash,
                @clientVersion, @pipelineFingerprint, @plannedUnits, @version,
                @encryptedPayload);
            """;
        cmd.Parameters.AddWithValue("@scanId", scan.ScanId.Value.ToString());
        cmd.Parameters.AddWithValue("@status", (int)scan.Status);
        cmd.Parameters.AddWithValue("@createdAt", scan.CreatedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@updatedAt", scan.UpdatedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@rulePackHash", scan.RuleFingerprint);
        cmd.Parameters.AddWithValue("@clientVersion", scan.ClientFingerprint);
        cmd.Parameters.AddWithValue("@pipelineFingerprint", scan.PipelineFingerprint);
        cmd.Parameters.AddWithValue("@plannedUnits", scan.PlannedCount);
        cmd.Parameters.AddWithValue("@version", scan.Version);
        cmd.Parameters.AddWithValue("@encryptedPayload", encryptedJson);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ScanRun?> GetByIdAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT scan_id, status, created_at_utc, updated_at_utc, rule_pack_hash,
                client_version, pipeline_fingerprint, planned_units, version,
                encrypted_payload
            FROM scan_runs
            WHERE scan_id = @scanId;
            """;
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        return ReadScanRun(reader);
    }

    public async Task<IReadOnlyList<ScanRun>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT scan_id, status, created_at_utc, updated_at_utc, rule_pack_hash,
                client_version, pipeline_fingerprint, planned_units, version,
                encrypted_payload
            FROM scan_runs
            ORDER BY created_at_utc DESC;
            """;

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var scans = new List<ScanRun>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            scans.Add(ReadScanRun(reader));
        }

        return scans;
    }

    public async Task<IReadOnlyList<ScanRun>> ListByStatusAsync(
        IReadOnlyList<ScanStatus> statuses, CancellationToken cancellationToken = default)
    {
        if (statuses.Count == 0)
            return Array.Empty<ScanRun>();

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();

        // Build parameterized IN clause.
        var placeholders = new List<string>(statuses.Count);
        for (int i = 0; i < statuses.Count; i++)
        {
            var paramName = $"@status{i}";
            placeholders.Add(paramName);
            cmd.Parameters.AddWithValue(paramName, (int)statuses[i]);
        }

        cmd.CommandText = $"""
            SELECT scan_id, status, created_at_utc, updated_at_utc, rule_pack_hash,
                client_version, pipeline_fingerprint, planned_units, version,
                encrypted_payload
            FROM scan_runs
            WHERE status IN ({string.Join(", ", placeholders)})
            ORDER BY created_at_utc DESC;
            """;

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var scans = new List<ScanRun>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            scans.Add(ReadScanRun(reader));
        }

        return scans;
    }

    public async Task<bool> TryTransitionAsync(
        ScanId scanId,
        ScanStatus expectedStatus,
        long expectedVersion,
        ScanStatus nextStatus,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            UPDATE scan_runs
            SET status = @next, updated_at_utc = @now, version = version + 1
            WHERE scan_id = @id AND status = @expected AND version = @expectedVersion;
            """;
        cmd.Parameters.AddWithValue("@next", (int)nextStatus);
        cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", scanId.Value.ToString());
        cmd.Parameters.AddWithValue("@expected", (int)expectedStatus);
        cmd.Parameters.AddWithValue("@expectedVersion", expectedVersion);

        int rows = await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task UpdateAsync(ScanRun scan, CancellationToken cancellationToken = default)
    {
        var payload = new ScanRunPayload(Description: null);
        byte[] jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, ScanRunJsonContext.Default.ScanRunPayload));
        var encrypted = _protector.Protect(Table, scan.ScanId.Value.ToString(), Field, jsonBytes);
        byte[] encryptedJson = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(encrypted, ScanRunJsonContext.Default.EncryptedPayload));

        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        long oldVersion = scan.Version;
        cmd.CommandText = """
            UPDATE scan_runs
            SET status = @status, updated_at_utc = @updatedAt,
                encrypted_payload = @encryptedPayload, version = version + 1
            WHERE scan_id = @id AND version = @oldVersion;
            """;
        cmd.Parameters.AddWithValue("@status", (int)scan.Status);
        cmd.Parameters.AddWithValue("@updatedAt", scan.UpdatedAtUtc.ToString("O"));
        cmd.Parameters.AddWithValue("@encryptedPayload", encryptedJson);
        cmd.Parameters.AddWithValue("@id", scan.ScanId.Value.ToString());
        cmd.Parameters.AddWithValue("@oldVersion", oldVersion);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private ScanRun ReadScanRun(SqliteDataReader reader)
    {
        var id = new ScanId(Guid.Parse(reader.GetString(0)));
        var status = (ScanStatus)reader.GetInt32(1);
        var createdAt = DateTimeOffset.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture);
        var updatedAt = DateTimeOffset.Parse(reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture);
        var rulePackHash = reader.GetString(4);
        var clientVersion = reader.GetString(5);
        var pipelineFingerprint = reader.GetString(6);
        var plannedUnits = reader.GetInt64(7);
        var version = reader.GetInt64(8);

        // Decrypt payload (optional — may be null for legacy rows).
        if (!reader.IsDBNull(9))
        {
            byte[] encryptedJson = GetBlobBytes(reader, 9);
            var encryptedPayload = JsonSerializer.Deserialize(
                Encoding.UTF8.GetString(encryptedJson), ScanRunJsonContext.Default.EncryptedPayload);
            if (encryptedPayload is not null)
            {
                byte[] plaintext = _protector.Unprotect(Table, id.Value.ToString(), Field, encryptedPayload);
                // Payload deserialized for future use; currently unused.
                _ = JsonSerializer.Deserialize(plaintext, ScanRunJsonContext.Default.ScanRunPayload);
            }
        }

        return new ScanRun(id, status, createdAt, updatedAt, rulePackHash, clientVersion,
            pipelineFingerprint, plannedUnits, version);
    }

    private static byte[] GetBlobBytes(SqliteDataReader reader, int ordinal)
    {
        using var stream = reader.GetStream(ordinal);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }
}

// ---------- Payload DTO and JSON source-gen context ----------

internal sealed record ScanRunPayload(string? Description);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ScanRunPayload))]
[JsonSerializable(typeof(EncryptedPayload))]
internal partial class ScanRunJsonContext : JsonSerializerContext;
