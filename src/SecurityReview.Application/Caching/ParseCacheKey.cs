using System.Security.Cryptography;
using System.Text;

namespace SecurityReview.Application.Caching;

/// <summary>
/// Stable cache key for the parse stage. Every component is already a
/// fingerprint or version identifier — no raw file paths, values, or
/// secrets enter the key. Changing any single component produces a
/// different key (cache miss).
/// </summary>
public sealed class ParseCacheKey
{
    public string FileSha256 { get; }
    public string StreamIdentity { get; }
    public string ParserId { get; }
    public string ParserVersion { get; }
    public string LimitsProfile { get; }
    public string ContractVersion { get; }

    /// <summary>Lowercase hex-encoded SHA-256 of the canonical key material.</summary>
    public string Key => _key.Value;
    private readonly Lazy<string> _key;

    public ParseCacheKey(
        string fileSha256,
        string streamIdentity,
        string parserId,
        string parserVersion,
        string limitsProfile,
        string contractVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(streamIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(parserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(parserVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(limitsProfile);
        ArgumentException.ThrowIfNullOrWhiteSpace(contractVersion);

        FileSha256 = fileSha256;
        StreamIdentity = streamIdentity;
        ParserId = parserId;
        ParserVersion = parserVersion;
        LimitsProfile = limitsProfile;
        ContractVersion = contractVersion;

        _key = new Lazy<string>(ComputeKey, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    private string ComputeKey()
    {
        string canonical = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"parse|{FileSha256}|{StreamIdentity}|{ParserId}|{ParserVersion}|{LimitsProfile}|{ContractVersion}");
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexStringLower(hash);
    }
}
