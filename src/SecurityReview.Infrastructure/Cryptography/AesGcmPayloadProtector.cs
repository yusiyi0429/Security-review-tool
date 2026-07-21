using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Protects and unprotects byte payloads using AES-256-GCM with per-call
/// random 12-byte nonces, 16-byte authentication tags, and AAD binding to
/// table, record ID, and field name. Plaintext is bounded to 16 MiB.
/// Key material and staging buffers are zeroed on disposal.
/// </summary>
public sealed class AesGcmPayloadProtector : IPayloadProtector, IDisposable
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int MaxPlaintext = 16 * 1024 * 1024; // 16 MiB

    private readonly byte[] _key;
    private readonly string _keyId;
    private bool _disposed;

    public AesGcmPayloadProtector(byte[] key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(keyId);
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

        _key = new byte[KeySize];
        key.CopyTo(_key, 0);
        _keyId = keyId;
    }

    public EncryptedPayload Protect(string table, string recordId, string fieldName, byte[] plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length > MaxPlaintext)
            throw new ArgumentException(
                $"Plaintext exceeds maximum of {MaxPlaintext} bytes.", nameof(plaintext));

        byte[] nonce = new byte[NonceSize];
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        RandomNumberGenerator.Fill(nonce);

        try
        {
            byte[] aad = BuildAad(table, recordId, fieldName);
            using var aes = new AesGcm(_key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            throw;
        }

        return new EncryptedPayload(
            Version: 1,
            KeyId: _keyId,
            NonceBase64: Convert.ToBase64String(nonce),
            CiphertextBase64: Convert.ToBase64String(ciphertext),
            TagBase64: Convert.ToBase64String(tag));
    }

    public byte[] Unprotect(string table, string recordId, string fieldName, EncryptedPayload payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(payload);

        byte[] nonce = Convert.FromBase64String(payload.NonceBase64);
        byte[] ciphertext = Convert.FromBase64String(payload.CiphertextBase64);
        byte[] tag = Convert.FromBase64String(payload.TagBase64);
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
            byte[] aad = BuildAad(table, recordId, fieldName);
            using var aes = new AesGcm(_key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            // Clear staging buffers
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }

        return plaintext;
    }

    private static byte[] BuildAad(string table, string recordId, string fieldName)
    {
        return Encoding.UTF8.GetBytes($"v1|{table}|{recordId}|{fieldName}");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }
}
