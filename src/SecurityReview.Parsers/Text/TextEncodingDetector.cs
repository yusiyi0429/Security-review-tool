using System.Text;

namespace SecurityReview.Parsers.Text;

/// <summary>
/// Strict text encoding detection. Detection order:
/// 1. BOM-confirmed UTF-8 / UTF-16LE / UTF-16BE
/// 2. Strict UTF-8 decode with throwOnInvalidBytes
/// 3. UTF-16 zero-byte distribution heuristic + strict decode
/// 4. Strict GB18030 decoder
/// 5. Fallback: DecodeUnreliable with bytes processed, no lossy text
///
/// The code-pages provider is registered by this type so results do not depend
/// on unrelated callers or test execution order.
/// </summary>
public static class TextEncodingDetector
{
    static TextEncodingDetector()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    /// <summary>
    /// Detected encoding result — either a valid Encoding with the text decoded
    /// successfully, or a DecodeUnreliable marker.
    /// </summary>
    public sealed record DetectionResult(
        string EncodingName,
        string Text,
        bool IsReliable,
        long BytesProcessed,
        string? FailureReason)
    {
        public static DetectionResult Success(string encodingName, string text, long bytesProcessed) =>
            new(encodingName, text, true, bytesProcessed, null);

        public static DetectionResult Unreliable(string text, long bytesProcessed, string reason) =>
            new("unreliable", text, false, bytesProcessed, reason);
    }

    /// <summary>
    /// Detect the encoding of <paramref name="data"/> and decode it to a
    /// string. Returns a <see cref="DetectionResult"/> with the encoding name,
    /// decoded text, reliability flag, and bytes processed.
    /// </summary>
    public static DetectionResult DetectAndDecode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return DetectionResult.Success("utf-8", string.Empty, 0);

        // Step 1: BOM check
        if (TryDecodeBom(data, out DetectionResult? bomResult))
            return bomResult!;

        // Step 2: Strict UTF-8
        if (TryDecodeStrictUtf8(data, out DetectionResult? utf8Result))
            return utf8Result!;

        // Step 3: UTF-16 zero-byte heuristic
        if (TryDecodeUtf16Heuristic(data, out DetectionResult? utf16Result))
            return utf16Result!;

        // Step 4: Strict GB18030
        if (TryDecodeGb18030(data, out DetectionResult? gbResult))
            return gbResult!;

        // Step 5: DecodeUnreliable — best-effort with replacement fallback
        // We don't accept replacement-char output; instead decode with best-effort
        // and mark unreliable, recording bytes processed.
        return DecodeUnreliable(data);
    }

    private static bool TryDecodeBom(ReadOnlySpan<byte> data, out DetectionResult? result)
    {
        result = null;

        // UTF-8 BOM: EF BB BF
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
        {
            ReadOnlySpan<byte> withoutBom = data[3..];
            var utf8 = new UTF8Encoding(false, true);
            try
            {
                string text = utf8.GetString(withoutBom);
                result = DetectionResult.Success("utf-8-bom", text, data.Length);
                return true;
            }
            catch (DecoderFallbackException)
            {
                result = DecodeUnreliableWithBom(data, 3, "utf-8-bom-decode-failed");
                return true;
            }
        }

        // UTF-16LE BOM: FF FE
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
        {
            return TryDecodeUtf16(data, false, "utf-16le-bom", out result);
        }

        // UTF-16BE BOM: FE FF
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF)
        {
            return TryDecodeUtf16(data, true, "utf-16be-bom", out result);
        }

        return false;
    }

    private static bool TryDecodeUtf16(ReadOnlySpan<byte> data, bool bigEndian,
        string encodingName, out DetectionResult? result)
    {
        result = null;
        ReadOnlySpan<byte> withoutBom = data.Length >= 2 ? data[2..] : data;
        var enc = new UnicodeEncoding(bigEndian, false, true);
        try
        {
            string text = enc.GetString(withoutBom);
            result = DetectionResult.Success(encodingName, text, data.Length);
            return true;
        }
        catch (DecoderFallbackException)
        {
            result = DecodeUnreliableWithBom(data, 2, $"{encodingName}-decode-failed");
            return true;
        }
    }

    private static bool TryDecodeStrictUtf8(ReadOnlySpan<byte> data, out DetectionResult? result)
    {
        result = null;
        var utf8 = new UTF8Encoding(false, true);
        try
        {
            string text = utf8.GetString(data);
            result = DetectionResult.Success("utf-8", text, data.Length);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryDecodeUtf16Heuristic(ReadOnlySpan<byte> data, out DetectionResult? result)
    {
        result = null;

        // Heuristic: count zero bytes at even vs odd positions in the first 1024 bytes
        int sample = Math.Min(data.Length, 1024);
        int evenZeros = 0, oddZeros = 0;
        for (int i = 0; i < sample; i++)
        {
            if (data[i] == 0)
            {
                if (i % 2 == 0) evenZeros++;
                else oddZeros++;
            }
        }

        bool isLe = evenZeros > oddZeros && evenZeros > sample * 0.15;
        bool isBe = oddZeros > evenZeros && oddZeros > sample * 0.15;

        if (isLe)
        {
            return TryDecodeUtf16(data, false, "utf-16le-heuristic", out result);
        }
        else if (isBe)
        {
            return TryDecodeUtf16(data, true, "utf-16be-heuristic", out result);
        }

        return false;
    }

    private static bool TryDecodeGb18030(ReadOnlySpan<byte> data, out DetectionResult? result)
    {
        result = null;
        try
        {
            Encoding gb18030 = Encoding.GetEncoding(54936,
                EncoderFallback.ExceptionFallback,
                DecoderFallback.ExceptionFallback);
            string text = gb18030.GetString(data);
            if (!IsPlausibleText(text))
                return false;
            result = DetectionResult.Success("gb18030", text, data.Length);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            // CodePagesEncodingProvider not registered
            return false;
        }
    }

    private static bool IsPlausibleText(string text)
    {
        foreach (char value in text)
        {
            if (char.IsControl(value) && value is not ('\t' or '\n' or '\r' or '\f'))
                return false;
        }

        return true;
    }

    private static DetectionResult DecodeUnreliableWithBom(ReadOnlySpan<byte> data, int bomLength, string reason)
    {
        // No lossy text: a BOM claims a known encoding but decoding failed.
        // Return empty text — the caller treats IsReliable==false as untrusted.
        return DetectionResult.Unreliable(string.Empty, data.Length, reason);
    }

    private static DetectionResult DecodeUnreliable(ReadOnlySpan<byte> data)
    {
        // No lossy text: return empty text and the byte count.
        // The caller treats IsReliable==false as untrusted and must not
        // pass the (empty) text to detection pipelines.
        return DetectionResult.Unreliable(string.Empty, data.Length, "no_encoding_detected");
    }
}
