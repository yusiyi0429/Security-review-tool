using System.Text;

namespace SecurityReview.Parsers.Jvm;

/// <summary>
/// Decoder for the Modified UTF-8 encoding used in JVM class file
/// <c>CONSTANT_Utf8</c> entries. Differs from standard UTF-8 in that:
/// the null byte is encoded as the two-byte sequence <c>0xC0 0x80</c>,
/// supplementary characters are encoded as separate UTF-16 surrogate
/// pairs (each surrogate encoded as a three-byte standard UTF-8 sequence),
/// and there are no four-byte forms. The decoder does not throw — invalid
/// sequences are reported via <see cref="TryDecode"/>.
/// </summary>
public static class ModifiedUtf8Decoder
{
    /// <summary>Maximum length of a JVM CONSTANT_Utf8 entry (1 MiB).</summary>
    public const int MaxUtf8Length = 1_048_576;

    /// <summary>
    /// Try to decode <paramref name="data"/> as Modified UTF-8. Returns
    /// <c>true</c> on success and assigns the decoded string to
    /// <paramref name="value"/>; otherwise returns <c>false</c> and the
    /// failure reason to <paramref name="reason"/>.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> data, out string value, out string reason)
    {
        if (data.Length > MaxUtf8Length)
        {
            value = string.Empty;
            reason = "utf8_length_exceeds_max";
            return false;
        }

        var sb = new StringBuilder(data.Length);
        int i = 0;
        while (i < data.Length)
        {
            byte b = data[i];

            if (b == 0)
            {
                value = string.Empty;
                reason = "embedded_null";
                return false;
            }

            if (b <= 0x7F)
            {
                sb.Append((char)b);
                i++;
                continue;
            }

            if (b == 0xC0 && i + 1 < data.Length && data[i + 1] == 0x80)
            {
                // Modified null
                sb.Append('\0');
                i += 2;
                continue;
            }

            if ((b & 0xE0) == 0xC0)
            {
                if (i + 1 >= data.Length)
                {
                    value = string.Empty;
                    reason = "truncated_2byte";
                    return false;
                }
                byte b2 = data[i + 1];
                if ((b2 & 0xC0) != 0x80)
                {
                    value = string.Empty;
                    reason = "bad_continuation_2byte";
                    return false;
                }
                int cp = ((b & 0x1F) << 6) | (b2 & 0x3F);
                if (cp < 0x80)
                {
                    value = string.Empty;
                    reason = "overlong_2byte";
                    return false;
                }
                sb.Append((char)cp);
                i += 2;
                continue;
            }

            if ((b & 0xF0) == 0xE0)
            {
                if (i + 2 >= data.Length)
                {
                    value = string.Empty;
                    reason = "truncated_3byte";
                    return false;
                }
                byte b2 = data[i + 1];
                byte b3 = data[i + 2];
                if ((b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80)
                {
                    value = string.Empty;
                    reason = "bad_continuation_3byte";
                    return false;
                }
                int cp = ((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
                if (cp < 0x800)
                {
                    value = string.Empty;
                    reason = "overlong_3byte";
                    return false;
                }

                // Modified UTF-8 encodes supplementary characters as
                // separate UTF-16 surrogate pairs (each surrogate as a
                // standard 3-byte UTF-8 sequence).
                if (cp >= 0xD800 && cp <= 0xDFFF)
                {
                    value = string.Empty;
                    reason = "lone_surrogate";
                    return false;
                }

                if (cp > 0xFFFF)
                {
                    // Map supplementary code point to surrogate pair
                    cp -= 0x10000;
                    sb.Append((char)((cp >> 10) + 0xD800));
                    sb.Append((char)((cp & 0x3FF) + 0xDC00));
                }
                else
                {
                    sb.Append((char)cp);
                }
                i += 3;
                continue;
            }

            value = string.Empty;
            reason = "invalid_lead_byte";
            return false;
        }

        value = sb.ToString();
        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Convenience wrapper that throws when the bytes cannot be decoded.
    /// Only intended for tests that exercise the decoder on hand-built
    /// well-formed inputs.
    /// </summary>
    public static string DecodeOrThrow(ReadOnlySpan<byte> data)
    {
        if (!TryDecode(data, out string value, out string reason))
            throw new InvalidOperationException("Invalid Modified UTF-8: " + reason);
        return value;
    }
}
