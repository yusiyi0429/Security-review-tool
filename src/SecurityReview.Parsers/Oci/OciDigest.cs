using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SecurityReview.Parsers.Oci;

/// <summary>
/// SHA-256 content digest in OCI <c>sha256:&lt;hex&gt;</c> form.
/// Only lowercase hex is accepted. Comparison uses fixed-time operations
/// to avoid timing side-channels on the digest value.
/// </summary>
public sealed class OciDigest : IEquatable<OciDigest>
{
    private readonly byte[] _hash;
    private readonly string _value;

    private OciDigest(byte[] hash, string value)
    {
        _hash = hash;
        _value = value;
    }

    /// <summary>The canonical digest string (<c>sha256:&lt;64 hex&gt;</c>).</summary>
    public string Value => _value;

    /// <summary>The raw 32-byte SHA-256 hash.</summary>
    public ReadOnlySpan<byte> Hash => _hash;

    /// <summary>
    /// Parses <c>sha256:&lt;64 lowercase hex digits&gt;</c>. Throws
    /// <see cref="FormatException"/> on any deviation.
    /// </summary>
    public static OciDigest Parse(string input)
    {
        if (!TryParse(input, out OciDigest? result, out string? error))
        {
            throw new FormatException(error);
        }

        return result!;
    }

    /// <summary>
    /// Non-throwing parse returning a null result with a diagnostic on failure.
    /// </summary>
    public static bool TryParse(string input, out OciDigest? result, out string? error)
    {
        result = null;
        error = null;

        if (input is null)
        {
            error = "digest must not be null";
            return false;
        }

        const string prefix = "sha256:";
        if (!input.StartsWith(prefix, StringComparison.Ordinal))
        {
            error = "digest must start with 'sha256:'";
            return false;
        }

        string hex = input.Substring(prefix.Length);
        if (hex.Length != 64)
        {
            error = $"digest must have 64 hex characters, got {hex.Length}";
            return false;
        }

        byte[] hash = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            int hi = HexValue(hex[i * 2]);
            int lo = HexValue(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0)
            {
                error = $"invalid hex character at position {i * 2 + (hi < 0 ? 0 : 1)}";
                return false;
            }

            hash[i] = (byte)((hi << 4) | lo);
        }

        result = new OciDigest(hash, input);
        return true;
    }

    /// <summary>
    /// Fixed-time equality comparison of the underlying hash bytes.
    /// </summary>
    public bool Equals(OciDigest? other)
    {
        if (other is null) return false;
        return CryptographicOperations.FixedTimeEquals(_hash, other._hash);
    }

    public override bool Equals(object? obj) =>
        obj is OciDigest other && Equals(other);

    public override int GetHashCode()
    {
        // Leaking the first 4 bytes of the hash into the hash code is
        // acceptable: hash codes are not a timing channel.
        return BinaryPrimitives.ReadInt32LittleEndian(_hash);
    }

    public override string ToString() => _value;

    public static bool operator ==(OciDigest? left, OciDigest? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(OciDigest? left, OciDigest? right) =>
        !(left == right);

    /// <summary>
    /// Computes the SHA-256 digest of <paramref name="data"/>.
    /// </summary>
    public static OciDigest Compute(ReadOnlySpan<byte> data)
    {
        byte[] hash = SHA256.HashData(data);
        return FromHash(hash);
    }

    /// <summary>
    /// Wraps raw 32-byte SHA-256 hash bytes.
    /// </summary>
    public static OciDigest FromHash(byte[] hash)
    {
        if (hash.Length != 32)
            throw new ArgumentException("Hash must be 32 bytes.", nameof(hash));

        string hex = Convert.ToHexStringLower(hash);
        return new OciDigest(hash, $"sha256:{hex}");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        _ => -1,
    };
}
