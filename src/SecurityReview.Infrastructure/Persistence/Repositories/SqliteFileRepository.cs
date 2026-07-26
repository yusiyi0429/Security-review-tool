using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Persistence.Repositories;

public sealed class SqliteFileRepository : IFileRepository
{
    private readonly ISqliteConnectionFactory _factory;
    private readonly IPayloadProtector _protector;
    private readonly IValueFingerprintService _fingerprint;

    private const string Table = "file_records";
    private const string Field = "encrypted_payload";
    private const int BatchSize = 500;

    public SqliteFileRepository(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector,
        IValueFingerprintService fingerprint)
    {
        _factory = factory;
        _protector = protector;
        _fingerprint = fingerprint;
    }

    public async Task InsertAsync(ScanId scanId, FileRecord file, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = CreateInsertCommand(connection, scanId, file);
        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task InsertBatchAsync(ScanId scanId, IReadOnlyList<FileRecord> files, CancellationToken cancellationToken = default)
    {
        for (int offset = 0; offset < files.Count; offset += BatchSize)
        {
            int batchCount = Math.Min(BatchSize, files.Count - offset);
            await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var tx = connection.BeginTransaction();

            try
            {
                await using var cmd = connection.CreateCommand();
                PrepareInsertCommand(cmd);

                for (int i = 0; i < batchCount; i++)
                {
                    BindInsertParameters(cmd, scanId, files[offset + i]);
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

    public async Task UpdateAsync(
        ScanId scanId,
        FileRecord file,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            UPDATE file_records
            SET path_hmac = @pathHmac,
                content_sha256 = @contentSha256,
                size = @size,
                format_id = @formatId,
                coverage_status = @coverageStatus,
                encrypted_payload = @encryptedPayload
            WHERE file_id = @fileId AND scan_id = @scanId;
            """;
        cmd.Parameters.AddWithValue("@pathHmac",
            _fingerprint.Compute(file.RelativePath).HexString);
        cmd.Parameters.AddWithValue("@contentSha256",
            (object?)file.ContentSha256 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@size", file.Length);
        cmd.Parameters.AddWithValue("@formatId", (object?)file.FormatId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@coverageStatus", (int)file.Coverage);
        cmd.Parameters.AddWithValue("@encryptedPayload", EncryptPayload(file));
        cmd.Parameters.AddWithValue("@fileId", file.FileId.Value.ToString());
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        int affected = await cmd.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
        if (affected != 1)
        {
            throw new InvalidOperationException(
                $"File record {file.FileId.Value} was not updated.");
        }
    }

    public async Task<FileRecord?> GetByIdAsync(FileId fileId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT file_id, scan_id, path_hmac, content_sha256, size, format_id,
                coverage_status, parser_fingerprint, encrypted_payload
            FROM file_records
            WHERE file_id = @fileId;
            """;
        cmd.Parameters.AddWithValue("@fileId", fileId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;

        return ReadFileRecord(reader);
    }

    public async Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(
        ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT file_id, scan_id, path_hmac, content_sha256, size, format_id,
                coverage_status, parser_fingerprint, encrypted_payload
            FROM file_records
            WHERE scan_id = @scanId;
            """;
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var files = new List<FileRecord>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            files.Add(ReadFileRecord(reader));
        }

        return files;
    }

    public async Task<int> CountByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _factory.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM file_records WHERE scan_id = @scanId;";
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());

        object? result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    private SqliteCommand CreateInsertCommand(SqliteConnection connection, ScanId scanId, FileRecord file)
    {
        var cmd = connection.CreateCommand();
        PrepareInsertCommand(cmd);
        BindInsertParameters(cmd, scanId, file);
        return cmd;
    }

    private static void PrepareInsertCommand(SqliteCommand cmd)
    {
        cmd.CommandText = """
            INSERT INTO file_records (file_id, scan_id, path_hmac, content_sha256, size,
                format_id, coverage_status, parser_fingerprint, encrypted_payload)
            VALUES (@fileId, @scanId, @pathHmac, @contentSha256, @size, @formatId,
                @coverageStatus, @parserFingerprint, @encryptedPayload);
            """;
        cmd.Parameters.Add("@fileId", SqliteType.Text);
        cmd.Parameters.Add("@scanId", SqliteType.Text);
        cmd.Parameters.Add("@pathHmac", SqliteType.Text);
        cmd.Parameters.Add("@contentSha256", SqliteType.Text);
        cmd.Parameters.Add("@size", SqliteType.Integer);
        cmd.Parameters.Add("@formatId", SqliteType.Text);
        cmd.Parameters.Add("@coverageStatus", SqliteType.Integer);
        cmd.Parameters.Add("@parserFingerprint", SqliteType.Text);
        cmd.Parameters.Add("@encryptedPayload", SqliteType.Blob);
    }

    private void BindInsertParameters(SqliteCommand cmd, ScanId scanId, FileRecord file)
    {
        byte[] encryptedJson = EncryptPayload(file);

        cmd.Parameters["@fileId"].Value = file.FileId.Value.ToString();
        cmd.Parameters["@scanId"].Value = scanId.Value.ToString();
        cmd.Parameters["@pathHmac"].Value = _fingerprint.Compute(file.RelativePath).HexString;
        cmd.Parameters["@contentSha256"].Value = (object?)file.ContentSha256 ?? DBNull.Value;
        cmd.Parameters["@size"].Value = (object?)file.Length ?? DBNull.Value;
        cmd.Parameters["@formatId"].Value = (object?)file.FormatId ?? DBNull.Value;
        cmd.Parameters["@coverageStatus"].Value = (int)file.Coverage;
        cmd.Parameters["@parserFingerprint"].Value = DBNull.Value;
        cmd.Parameters["@encryptedPayload"].Value = encryptedJson;
    }

    private byte[] EncryptPayload(FileRecord file)
    {
        var payload = new FileRecordPayload(
            RelativePath: file.RelativePath,
            EncryptedPathPlaceholder: file.EncryptedPathPlaceholder,
            StreamName: file.StreamName,
            LastWriteUtc: file.LastWriteUtc.ToString("O"),
            Attributes: (int)file.Attributes,
            RootIndex: file.RootIndex,
            ComponentAssetTypes: file.ComponentAssetTypes.Select(AssetTypeIdToInt).ToArray(),
            InventoryStatus: (int)file.Status,
            VolumeSerial: file.Identity.VolumeSerial,
            FileIndexLower: (ulong)(file.Identity.FileIndex & ulong.MaxValue),
            FileIndexUpper: (ulong)(file.Identity.FileIndex >> 64),
            IdentityStreamName: file.Identity.StreamName);

        byte[] jsonBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, FileRecordJsonContext.Default.FileRecordPayload));
        var encrypted = _protector.Protect(Table, file.FileId.Value.ToString(), Field, jsonBytes);
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(encrypted, FileRecordJsonContext.Default.EncryptedPayload));
    }

    private FileRecord ReadFileRecord(SqliteDataReader reader)
    {
        var fileId = new FileId(Guid.Parse(reader.GetString(0)));
        // Skip scan_id at index 1 (not needed for reconstruction)
        // Skip path_hmac at index 2
        string? contentSha256 = reader.IsDBNull(3) ? null : reader.GetString(3);
        long length = reader.IsDBNull(4) ? 0 : reader.GetInt64(4);
        string? formatId = reader.IsDBNull(5) ? null : reader.GetString(5);
        var coverage = (CoverageStatus)reader.GetInt32(6);
        // Skip parser_fingerprint at index 7

        byte[] encryptedJson = GetBlobBytes(reader, 8);
        var encryptedPayload = JsonSerializer.Deserialize(
            Encoding.UTF8.GetString(encryptedJson), FileRecordJsonContext.Default.EncryptedPayload)!;

        byte[] plaintext = _protector.Unprotect(Table, fileId.Value.ToString(), Field, encryptedPayload);
        var payload = JsonSerializer.Deserialize(plaintext, FileRecordJsonContext.Default.FileRecordPayload)!;

        var identity = new FileStreamIdentity(
            payload.VolumeSerial,
            new UInt128(payload.FileIndexUpper, payload.FileIndexLower),
            payload.IdentityStreamName);

        var assetTypes = payload.ComponentAssetTypes
            .Select(i => AssetTypeId.Parse($"ASSET-{i:000}"))
            .ToArray();

        return new FileRecord(
            FileId: fileId,
            RootIndex: payload.RootIndex,
            RelativePath: payload.RelativePath,
            EncryptedPathPlaceholder: payload.EncryptedPathPlaceholder,
            StreamName: payload.StreamName,
            Length: length,
            LastWriteUtc: DateTimeOffset.Parse(payload.LastWriteUtc, System.Globalization.CultureInfo.InvariantCulture),
            Attributes: (FileAttributes)payload.Attributes,
            Identity: identity,
            ComponentAssetTypes: assetTypes,
            Status: (InventoryStatus)payload.InventoryStatus,
            FormatId: formatId,
            ContentSha256: contentSha256,
            Coverage: coverage);
    }

    private static int AssetTypeIdToInt(AssetTypeId id) =>
        int.Parse(id.Value.AsSpan(6), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture);

    private static byte[] GetBlobBytes(SqliteDataReader reader, int ordinal)
    {
        using var stream = reader.GetStream(ordinal);
        byte[] buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }
}

// ---------- Payload DTO and JSON source-gen context ----------

internal sealed record FileRecordPayload(
    string RelativePath,
    string? EncryptedPathPlaceholder,
    string? StreamName,
    string LastWriteUtc,
    int Attributes,
    int RootIndex,
    int[] ComponentAssetTypes,
    int InventoryStatus,
    string VolumeSerial,
    ulong FileIndexLower,
    ulong FileIndexUpper,
    string? IdentityStreamName);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(FileRecordPayload))]
[JsonSerializable(typeof(EncryptedPayload))]
internal partial class FileRecordJsonContext : JsonSerializerContext;
