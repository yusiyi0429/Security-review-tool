using System.Security.Cryptography;
using System.Text;

namespace SecurityReview.Application.Caching;

/// <summary>
/// Stable cache key for the detection stage. Wraps a parse-stage key plus
/// the detection-specific inputs. Changing any component — including the
/// parse key — produces a different key (cache miss).
/// </summary>
public sealed class DetectionCacheKey
{
    public ParseCacheKey ParseKey { get; }
    public string PolicySha256 { get; }
    public string DetectorBundleVersion { get; }

    /// <summary>Lowercase hex-encoded SHA-256 of the canonical key material.</summary>
    public string Key => _key.Value;
    private readonly Lazy<string> _key;

    public DetectionCacheKey(
        ParseCacheKey parseKey,
        string policySha256,
        string detectorBundleVersion)
    {
        ArgumentNullException.ThrowIfNull(parseKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(policySha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(detectorBundleVersion);

        ParseKey = parseKey;
        PolicySha256 = policySha256;
        DetectorBundleVersion = detectorBundleVersion;

        _key = new Lazy<string>(ComputeKey, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    private string ComputeKey()
    {
        string canonical = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"detect|{ParseKey.Key}|{PolicySha256}|{DetectorBundleVersion}");
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexStringLower(hash);
    }
}
