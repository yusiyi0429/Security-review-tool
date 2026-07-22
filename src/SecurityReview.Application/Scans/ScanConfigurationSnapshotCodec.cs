using System.Text;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Serializes and protects immutable scan configuration snapshots. Keeping
/// the AAD tuple in one place prevents the read and write paths from drifting.
/// </summary>
public sealed class ScanConfigurationSnapshotCodec
{
    private const string TableName = "scan_config_snapshots";
    private const string FieldName = "encrypted_payload";

    private readonly IPayloadProtector _protector;

    public ScanConfigurationSnapshotCodec(IPayloadProtector protector)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
    }

    public byte[] Protect(ScanId scanId, ScanConfigurationSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        byte[] plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot));
        EncryptedPayload envelope = _protector.Protect(
            TableName,
            scanId.Value.ToString(),
            FieldName,
            plaintext);

        return JsonSerializer.SerializeToUtf8Bytes(
            envelope,
            SnapshotJsonContext.Default.EncryptedPayload);
    }

    public ScanConfigurationSnapshot Unprotect(ScanSnapshotRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        EncryptedPayload envelope = JsonSerializer.Deserialize(
            record.EncryptedPayload,
            SnapshotJsonContext.Default.EncryptedPayload)
            ?? throw new InvalidDataException("The scan snapshot envelope is empty.");

        byte[] plaintext = _protector.Unprotect(
            TableName,
            record.ScanId.Value.ToString(),
            FieldName,
            envelope);

        ScanConfigurationSnapshot snapshot = JsonSerializer.Deserialize<ScanConfigurationSnapshot>(
            plaintext)
            ?? throw new InvalidDataException("The scan snapshot payload is empty.");

        if (!string.Equals(snapshot.ComputeHash(), record.ConfigHash, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The scan snapshot hash does not match its record.");
        }

        return snapshot;
    }
}
