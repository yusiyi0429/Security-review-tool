using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Stores named secrets (e.g., LLM API credentials) protected with DPAPI
/// CurrentUser and name-derived optional entropy. Secret values are stored
/// as individual files whose filenames are SHA-256 hashes of the logical
/// name — the name and value are never written in plaintext to disk.
/// </summary>
public sealed class WindowsDpapiSecretStore : ISecretStore
{
    private readonly string _storeDirectory;

    /// <summary>
    /// Creates the secret store rooted at <c>{paths.Config}/secrets/</c>.
    /// </summary>
    public WindowsDpapiSecretStore(AppDataPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _storeDirectory = Path.Combine(paths.Config, "secrets");
    }

    /// <summary>
    /// Creates the secret store rooted at an arbitrary directory (for testing).
    /// </summary>
    public WindowsDpapiSecretStore(string storeDirectory)
    {
        ArgumentNullException.ThrowIfNull(storeDirectory);
        _storeDirectory = storeDirectory;
    }

    public void Save(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Secret name cannot be empty.", nameof(name));

        Directory.CreateDirectory(_storeDirectory);

        string filePath = GetSecretFilePath(name);
        byte[] plaintext = Encoding.UTF8.GetBytes(value);
        byte[] entropy = DeriveEntropy(name);

        byte[] protectedData = System.Security.Cryptography.ProtectedData.Protect(
            plaintext, entropy, DataProtectionScope.CurrentUser);

        // Atomic write
        string tmpFile = filePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(tmpFile, protectedData);
            File.Move(tmpFile, filePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmpFile); } catch { /* best effort */ }
            throw;
        }
    }

    public string Load(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        string filePath = GetSecretFilePath(name);
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Secret '{name}' not found.");

        byte[] protectedData = File.ReadAllBytes(filePath);
        byte[] entropy = DeriveEntropy(name);

        byte[] plaintext;
        try
        {
            plaintext = System.Security.Cryptography.ProtectedData.Unprotect(
                protectedData, entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                $"Cannot decrypt secret '{name}'. It may belong to a different user or be corrupted.", ex);
        }

        return Encoding.UTF8.GetString(plaintext);
    }

    public void Delete(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        string filePath = GetSecretFilePath(name);
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
    }

    /// <summary>
    /// Returns the storage path for a named secret. The filename is SHA-256 of
    /// the logical name (lowercase hex), not the credential text or endpoint.
    /// </summary>
    private string GetSecretFilePath(string name)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(name));
        string fileName = Convert.ToHexStringLower(hash);
        return Path.Combine(_storeDirectory, fileName);
    }

    /// <summary>
    /// Derives DPAPI optional entropy from the secret name using HKDF-SHA256
    /// with empty salt and a fixed info string.
    /// </summary>
    private static byte[] DeriveEntropy(string name)
    {
        byte[] ikm = Encoding.UTF8.GetBytes(name);
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256, ikm, 32, salt: [],
            "SecurityReviewTool/v1/secret-entropy"u8.ToArray());
    }
}
