using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Generates a random 32-byte HMAC key per process lifetime, normalizes only
/// detector-approved whitespace/case rules, computes HMAC-SHA256 over UTF-8
/// bytes, clears temporary byte buffers, and disposes/zeros the key when the
/// process exits. P4 replaces this with DPAPI-backed persistent key.
/// </summary>
public sealed class EphemeralValueFingerprintService : IValueFingerprintService, IDisposable
{
    private readonly byte[] _hmacKey;

    public EphemeralValueFingerprintService()
    {
        _hmacKey = new byte[32];
        RandomNumberGenerator.Fill(_hmacKey);
    }

    public ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue)
    {
        // Normalize: trim whitespace, collapse internal whitespace, lowercase
        string normalized = NormalizeValue(normalizedValue);

        byte[] rented = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(normalized.Length));
        try
        {
            int byteCount = Encoding.UTF8.GetBytes(normalized, rented);
            byte[] hash = HMACSHA256.HashData(_hmacKey, rented.AsSpan(0, byteCount));
            string hex = Convert.ToHexStringLower(hash);

            // Clear the rented buffer — the hash is already copied to hex string
            CryptographicOperations.ZeroMemory(rented.AsSpan(0, byteCount));

            return new ValueFingerprint(hex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// Normalize whitespace and case. Whitespace is trimmed from both ends;
    /// internal whitespace runs are collapsed to a single space. Case is
    /// lowered for grouping purposes. This is the only normalization allowed:
    /// no Unicode normalization form changes (NFC/NFD/NFKC), no diacritic
    /// stripping, no punctuation folding.
    /// </summary>
    internal static string NormalizeValue(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty) return string.Empty;

        // Trim leading and trailing whitespace
        int start = 0;
        int end = value.Length - 1;
        while (start <= end && char.IsWhiteSpace(value[start])) start++;
        while (end >= start && char.IsWhiteSpace(value[end])) end--;

        if (start > end) return string.Empty;

        int len = end - start + 1;
        // Fast path: no internal whitespace to collapse, already lowercase ASCII
        bool needsCollapse = false;
        for (int i = start; i <= end; i++)
        {
            if (char.IsWhiteSpace(value[i]) && i + 1 <= end && char.IsWhiteSpace(value[i + 1]))
            {
                needsCollapse = true;
                break;
            }
        }

        if (!needsCollapse)
        {
            // Just trim + lowercase
            return value.Slice(start, len).ToString().ToLowerInvariant();
        }

        // Slow path: collapse internal whitespace
        Span<char> buffer = len <= 256
            ? stackalloc char[len]
            : new char[len];
        int pos = 0;
        bool lastWasSpace = false;
        for (int i = start; i <= end; i++)
        {
            char c = value[i];
            if (char.IsWhiteSpace(c))
            {
                if (!lastWasSpace && pos > 0)
                {
                    buffer[pos++] = ' ';
                    lastWasSpace = true;
                }
            }
            else
            {
                buffer[pos++] = char.ToLowerInvariant(c);
                lastWasSpace = false;
            }
        }

        string result = new(buffer[..pos]);
        return result;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_hmacKey);
    }
}
