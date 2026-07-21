using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Manages a DPAPI CurrentUser-protected 32-byte master key stored on disk.
/// On first use, generates a fresh key + 8-byte key ID, DPAPI-protects the
/// key, and atomically writes <c>keyring.dat</c> with current-user-only ACL.
/// Reloads the same key from disk on subsequent uses.
/// Never auto-regenerates if an existing keyring cannot be decrypted — that
/// would make history silently unreadable.
/// </summary>
public sealed class WindowsDpapiKeyRing : IDisposable
{
    private const int MasterKeyLength = 32;
    private const int KeyIdByteLength = 8;
    private const int ExpectedSchemaVersion = 1;

    private readonly byte[] _masterKey;
    private readonly string _keyId;
    private readonly HkdfSha256 _hkdf;
    private bool _disposed;

    private WindowsDpapiKeyRing(byte[] masterKey, string keyId)
    {
        _masterKey = masterKey;
        _keyId = keyId;
        _hkdf = new HkdfSha256(_masterKey);
    }

    /// <summary>
    /// Hex-encoded 8-byte key identifier (16 hex chars).
    /// </summary>
    public string KeyId => _keyId;

    /// <summary>
    /// HKDF-SHA256 key derivation from the master key.
    /// </summary>
    public HkdfSha256 Hkdf => _hkdf;

    /// <summary>
    /// Loads the existing keyring from <paramref name="paths"/>.KeyRingFile,
    /// or creates a fresh one if none exists. Throws if the file exists but
    /// cannot be parsed, validated, or DPAPI-unprotected.
    /// </summary>
    public static WindowsDpapiKeyRing LoadOrCreate(AppDataPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        paths.EnsureCreated();

        string keyRingFile = paths.KeyRingFile;

        if (File.Exists(keyRingFile))
            return Load(keyRingFile);

        return Create(keyRingFile);
    }

    private static WindowsDpapiKeyRing Create(string keyRingFile)
    {
        // Generate master key and key ID
        byte[] masterKey = new byte[MasterKeyLength];
        byte[] keyIdBytes = new byte[KeyIdByteLength];
        RandomNumberGenerator.Fill(masterKey);
        RandomNumberGenerator.Fill(keyIdBytes);

        string keyId = Convert.ToHexStringLower(keyIdBytes);

        // DPAPI-protect the master key
        byte[] protectedData = System.Security.Cryptography.ProtectedData.Protect(
            masterKey, optionalEntropy: null, DataProtectionScope.CurrentUser);

        // Build document
        var doc = new KeyRingDocument
        {
            schema_version = ExpectedSchemaVersion,
            key_id = keyId,
            protected_data_base64 = Convert.ToBase64String(protectedData),
            created_at_utc = DateTime.UtcNow.ToString("O")
        };

        // Atomic write: write to a temporary sibling file, then move
        string dir = Path.GetDirectoryName(keyRingFile)!;
        string tmpFile = Path.Combine(dir, $".keyring-{Guid.NewGuid():N}.tmp");
        try
        {
            string json = JsonSerializer.Serialize(doc, KeyRingDocumentJsonContext.Default.KeyRingDocument);
            File.WriteAllText(tmpFile, json);
            File.Move(tmpFile, keyRingFile);
        }
        catch
        {
            // Clean up temp file on failure
            try { File.Delete(tmpFile); } catch { /* best effort */ }
            throw;
        }

        return new WindowsDpapiKeyRing(masterKey, keyId);
    }

    private static WindowsDpapiKeyRing Load(string keyRingFile)
    {
        // Reject reparse points / non-regular files
        var fileInfo = new FileInfo(keyRingFile);
        if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"Keyring file '{keyRingFile}' is a reparse point.");

        // Read and parse JSON
        string json;
        try
        {
            json = File.ReadAllText(keyRingFile);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to read keyring file: {ex.Message}", ex);
        }

        KeyRingDocument doc;
        try
        {
            doc = JsonSerializer.Deserialize(json, KeyRingDocumentJsonContext.Default.KeyRingDocument)
                  ?? throw new InvalidOperationException("Keyring file is empty or null.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Keyring file contains invalid JSON: {ex.Message}", ex);
        }

        // Validate schema version
        if (doc.schema_version != ExpectedSchemaVersion)
            throw new InvalidOperationException(
                $"Unsupported keyring schema version: {doc.schema_version}. Expected: {ExpectedSchemaVersion}.");

        // Validate key_id
        if (string.IsNullOrWhiteSpace(doc.key_id) || doc.key_id.Length != KeyIdByteLength * 2)
            throw new InvalidOperationException("Keyring contains invalid or missing key_id.");

        // Decode and validate protected_data
        byte[] protectedData;
        try
        {
            protectedData = Convert.FromBase64String(doc.protected_data_base64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Keyring protected_data_base64 is not valid base64.", ex);
        }

        // DPAPI-unprotect
        byte[] masterKey;
        try
        {
            masterKey = System.Security.Cryptography.ProtectedData.Unprotect(
                protectedData, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                "Cannot decrypt keyring. The file may belong to a different user or be corrupted.", ex);
        }

        // Validate key length
        if (masterKey.Length != MasterKeyLength)
            throw new InvalidOperationException(
                $"Unprotected key has wrong length: {masterKey.Length}. Expected: {MasterKeyLength}.");

        return new WindowsDpapiKeyRing(masterKey, doc.key_id);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        CryptographicOperations.ZeroMemory(_masterKey);
        _hkdf.Dispose();
    }
}
