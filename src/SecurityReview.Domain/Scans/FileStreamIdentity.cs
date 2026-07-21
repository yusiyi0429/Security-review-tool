using System.Security.Cryptography;
using System.Text;

namespace SecurityReview.Domain.Scans;

// Stable stream identity: volume serial plus the 128-bit NTFS file index plus
// the optional ADS name. A path is never used as identity.
public sealed record FileStreamIdentity(string VolumeSerial, UInt128 FileIndex, string? StreamName)
{
    // Task-local UUIDv5 (RFC 4122 §4.3, SHA-1): the scan ID namespaces the name
    // so identities never collide across scans. The database stores an HMAC
    // path fingerprint separately; this value is for in-task correlation only.
    public FileId DeriveFileId(ScanId scanId)
    {
        string canonical = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"{VolumeSerial}:{FileIndex:X32}:{StreamName ?? string.Empty}");
        byte[] nameBytes = Encoding.UTF8.GetBytes(canonical);
        byte[] namespaceBytes = scanId.Value.ToByteArray();
        byte[] input = new byte[namespaceBytes.Length + nameBytes.Length];
        namespaceBytes.CopyTo(input, 0);
        nameBytes.CopyTo(input, namespaceBytes.Length);
#pragma warning disable CA5350 // UUIDv5 (RFC 4122 §4.3) mandates SHA-1; this is a deterministic task-local identifier, not a security primitive.
        byte[] hash = SHA1.HashData(input);
#pragma warning restore CA5350
        Span<byte> uuid = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(uuid);
        uuid[7] = (byte)((uuid[7] & 0x0F) | (5 << 4));
        uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80);
        return new FileId(new Guid(uuid));
    }
}
