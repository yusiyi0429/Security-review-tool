using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteCoverageRepository : ICoverageRepository
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;

    private const string Table = "coverage_gaps";
    private const string Field = "encrypted_payload";
    private const int BatchSize = 500;

    public SqliteCoverageRepository(ISqliteConnectionFactory factory, IPayloadProtector protector)
    {
        _factory = factory;
        _protector = protector;
    }

    public async Task InsertAsync(CoverageGap gap, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = CreateInsertCommand(connection, gap);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task InsertBatchAsync(IReadOnlyList<CoverageGap> gaps, CancellationToken cancellationToken = default)
    {
        for (int offset = 0; offset < gaps.Count; offset += BatchSize)
        {
            int batchCount = Math.Min(BatchSize, gaps.Count - offset);
            await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var tx = connection.BeginTransaction();

            try
            {
                await using var cmd = connection.CreateCommand();
                PrepareInsertCommand(cmd);

                for (int i = 0; i < batchCount; i++)
                {
                    BindInsertParameters(cmd, gaps[offset + i]);
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw;
            }
        }
    }

    public async Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(
        ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT gap_id, scan_id, file_id, stage, reason, detail_code,
                planned_bytes, processed_bytes, encrypted_payload
            FROM coverage_gaps
            WHERE scan_id = @scanId;
            """;
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var gaps = new List<CoverageGap>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            gaps.Add(ReadCoverageGap(reader));
        }

        return gaps;
    }

    private SqliteCommand CreateInsertCommand(SqliteConnection connection, CoverageGap gap)
    {
        var cmd = connection.CreateCommand();
        PrepareInsertCommand(cmd);
        BindInsertParameters(cmd, gap);
        return cmd;
    }

    private static void PrepareInsertCommand(SqliteCommand cmd)
    {
        cmd.CommandText = """
            INSERT INTO coverage_gaps (gap_id, scan_id, file_id, stage, reason, detail_code,
                planned_bytes, processed_bytes, encrypted_payload)
            VALUES (@gapId, @scanId, @fileId, @stage, @reason, @detailCode,
                @plannedBytes, @processedBytes, @encryptedPayload);
            """;
        cmd.Parameters.Add("@gapId", SqliteType.Text);
        cmd.Parameters.Add("@scanId", SqliteType.Text);
        cmd.Parameters.Add("@fileId", SqliteType.Text);
        cmd.Parameters.Add("@stage", SqliteType.Text);
        cmd.Parameters.Add("@reason", SqliteType.Integer);
        cmd.Parameters.Add("@detailCode", SqliteType.Text);
        cmd.Parameters.Add("@plannedBytes", SqliteType.Integer);
        cmd.Parameters.Add("@processedBytes", SqliteType.Integer);
        cmd.Parameters.Add("@encryptedPayload", SqliteType.Blob);
    }

    private void BindInsertParameters(SqliteCommand cmd, CoverageGap gap)
    {
        byte[] encryptedJson = EncryptPayload(gap);

        cmd.Parameters["@gapId"].Value = gap.GapId.ToString();
        cmd.Parameters["@scanId"].Value = gap.ScanId.Value.ToString();
        cmd.Parameters["@fileId"].Value = (object?)gap.FileId?.Value.ToString() ?? DBNull.Value;
        cmd.Parameters["@stage"].Value = gap.Stage;
        cmd.Parameters["@reason"].Value = (int)gap.Reason;
        cmd.Parameters["@detailCode"].Value = gap.DetailCode;
        cmd.Parameters["@plannedBytes"].Value = (object?)gap.PlannedBytes ?? DBNull.Value;
        cmd.Parameters["@processedBytes"].Value = (object?)gap.ProcessedBytes ?? DBNull.Value;
        cmd.Parameters["@encryptedPayload"].Value = encryptedJson;
    }

    private byte[] EncryptPayload(CoverageGap gap)
    {
        var payload = new CoverageGapPayload(
            VirtualPath: gap.VirtualPath,
            FormatId: gap.FormatId,
            CreatedAtUtc: gap.CreatedAtUtc.ToString("O"));

        byte[] jsonBytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(payload, CoverageGapJsonContext.Default.CoverageGapPayload));
        var encrypted = _protector.Protect(Table, gap.GapId.ToString(), Field, jsonBytes);
        return Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(encrypted, CoverageGapJsonContext.Default.EncryptedPayload));
    }

    private CoverageGap ReadCoverageGap(SqliteDataReader reader)
    {
        var gapId = Guid.Parse(reader.GetString(0));
        var scanId = new ScanId(Guid.Parse(reader.GetString(1)));
        FileId? fileId = reader.IsDBNull(2) ? null : new FileId(Guid.Parse(reader.GetString(2)));
        var stage = reader.GetString(3);
        var reason = (GapReason)reader.GetInt32(4);
        var detailCode = reader.GetString(5);
        long? plannedBytes = reader.IsDBNull(6) ? null : reader.GetInt64(6);
        long? processedBytes = reader.IsDBNull(7) ? null : reader.GetInt64(7);

        byte[] encryptedJson = GetBlobBytes(reader, 8);
        var encryptedPayload = JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(encryptedJson), CoverageGapJsonContext.Default.EncryptedPayload)!;

        byte[] plaintext = _protector.Unprotect(Table, gapId.ToString(), Field, encryptedPayload);
        var payload = JsonSerializer.Deserialize(plaintext, CoverageGapJsonContext.Default.CoverageGapPayload)!;

        return new CoverageGap(
            GapId: gapId,
            ScanId: scanId,
            FileId: fileId,
            VirtualPath: payload.VirtualPath,
            FormatId: payload.FormatId,
            Stage: stage,
            Reason: reason,
            DetailCode: detailCode,
            PlannedBytes: plannedBytes,
            ProcessedBytes: processedBytes,
            CreatedAtUtc: DateTimeOffset.Parse(payload.CreatedAtUtc, System.Globalization.CultureInfo.InvariantCulture));
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

internal sealed record CoverageGapPayload(
    string VirtualPath,
    string FormatId,
    string CreatedAtUtc);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CoverageGapPayload))]
[JsonSerializable(typeof(EncryptedPayload))]
internal partial class CoverageGapJsonContext : JsonSerializerContext;
