using System.Security.Cryptography;
using System.Text;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Derives independent 32-byte encryption and HMAC fingerprinting keys from a
/// master key using HKDF-SHA256 (RFC 5869) with empty salt and service-specific
/// info strings. Both the master key and derived keys are zeroed on disposal.
/// </summary>
public sealed class HkdfSha256 : IDisposable
{
    private static readonly byte[] EmptySalt = [];
    private static readonly byte[] EncryptionInfo = "SecurityReviewTool/v1/encryption"u8.ToArray();
    private static readonly byte[] FingerprintInfo = "SecurityReviewTool/v1/fingerprint"u8.ToArray();

    private readonly byte[] _masterKey;
    private byte[]? _encryptionKey;
    private byte[]? _fingerprintKey;
    private bool _disposed;

    public HkdfSha256(byte[] masterKey)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.Length != 32)
            throw new ArgumentException("Master key must be 32 bytes.", nameof(masterKey));

        _masterKey = new byte[32];
        masterKey.CopyTo(_masterKey, 0);
    }

    public byte[] DeriveEncryptionKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _encryptionKey ??= HKDF.DeriveKey(HashAlgorithmName.SHA256, _masterKey, 32, EmptySalt, EncryptionInfo);
        return _encryptionKey;
    }

    public byte[] DeriveFingerprintKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _fingerprintKey ??= HKDF.DeriveKey(HashAlgorithmName.SHA256, _masterKey, 32, EmptySalt, FingerprintInfo);
        return _fingerprintKey;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        CryptographicOperations.ZeroMemory(_masterKey);
        if (_encryptionKey is not null) CryptographicOperations.ZeroMemory(_encryptionKey);
        if (_fingerprintKey is not null) CryptographicOperations.ZeroMemory(_fingerprintKey);
    }
}
