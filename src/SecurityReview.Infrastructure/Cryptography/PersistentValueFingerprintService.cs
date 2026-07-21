using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// Computes a persistent, keyed HMAC-SHA256 fingerprint of a normalized
/// finding value. Uses a DPAPI-backed persistent key (via HKDF) so
/// fingerprints remain stable across process restarts, enabling cross-session
/// grouping. Normalization applies NFKC Unicode normalization followed by
/// detector-approved whitespace/case rules.
/// </summary>
public sealed class PersistentValueFingerprintService : IValueFingerprintService, IDisposable
{
    private readonly byte[] _hmacKey;
    private bool _disposed;

    /// <summary>
    /// Creates the service with a derived fingerprint key (32 bytes).
    /// </summary>
    public PersistentValueFingerprintService(byte[] fingerprintKey)
    {
        ArgumentNullException.ThrowIfNull(fingerprintKey);
        if (fingerprintKey.Length != 32)
            throw new ArgumentException("Fingerprint key must be 32 bytes.", nameof(fingerprintKey));

        _hmacKey = new byte[32];
        fingerprintKey.CopyTo(_hmacKey, 0);
    }

    public ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Step 1: NFKC normalization
        string nfkc = normalizedValue.IsEmpty ? "" : normalizedValue.ToString().Normalize(NormalizationForm.FormKC);

        // Step 2: Detector-approved whitespace/case normalization
        string normalized = NormalizeValue(nfkc);

        // Step 3: HMAC-SHA256
        byte[] rented = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(normalized.Length));
        try
        {
            int byteCount = Encoding.UTF8.GetBytes(normalized, rented);
            byte[] hash = HMACSHA256.HashData(_hmacKey, rented.AsSpan(0, byteCount));
            string hex = Convert.ToHexStringLower(hash);

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
    /// lowered for grouping purposes.
    /// </summary>
    internal static string NormalizeValue(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty) return string.Empty;

        int start = 0;
        int end = value.Length - 1;
        while (start <= end && char.IsWhiteSpace(value[start])) start++;
        while (end >= start && char.IsWhiteSpace(value[end])) end--;

        if (start > end) return string.Empty;

        int len = end - start + 1;
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
            return value.Slice(start, len).ToString().ToLowerInvariant();
        }

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

        return new string(buffer[..pos]);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_hmacKey);
    }
}
