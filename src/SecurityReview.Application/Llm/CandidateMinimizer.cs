using System.Text;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Bounded renderer of one semantic-review candidate payload.
///
/// Produces a <see cref="MinimizedCandidate"/> with the following
/// invariants:
///   * <c>UntrustedContext</c> never contains the original absolute
///     path of the source asset — only the extension and content kind
///     are surfaced.
///   * <c>UntrustedContext</c> is masked first, then cropped
///     symmetrically around the candidate locator, on Unicode scalar
///     boundaries.
///   * The total packed UTF-8 byte length of the rendered candidate
///     payload stays within the 16 KiB budget. If even an empty
///     context cannot fit, the minimizer still returns a payload —
///     callers must additionally check <c>PackedUtf8ByteLength</c>
///     against their outer request budget.
///   * If the candidate value is itself identified as a deterministic
///     secret, <c>RedactedCandidateValue</c> is the matching
///     <c>[REDACTED:SENS-xxx]</c> token; otherwise it is the original
///     value, unaltered.
/// </summary>
public static class CandidateMinimizer
{
    /// <summary>UTF-8 byte ceiling for the rendered candidate payload.</summary>
    public const int CandidateByteBudget = 16 * 1024;

    private const int MinContextReservation = 64;
    private const string FallbackCategory = "SENS-001";

    /// <summary>
    /// Render the request into a bounded candidate payload.
    /// </summary>
    public static MinimizedCandidate Minimize(SemanticReviewRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        string contentKind = NormalizeContentKind(request.ContentKind);
        string extension = NormalizeExtension(request.Extension);
        string maskedContext = NormalizeUntrustedText(
            DeterministicSecretMasker.Mask(request.FullContext, request.DeterministicSecrets));
        string redactedValue = NormalizeUntrustedText(ComputeRedactedCandidateValue(
            request.CandidateValue, request.FullContext, request.CandidateLocator,
            request.DeterministicSecrets));
        long redactions = CountSecretRedactions(maskedContext);

        var (untrustedContext, leftTrunc, rightTrunc) =
            CropAroundLocator(maskedContext, request.FullContext, request.CandidateLocator);

        CategoryId category = request.CategoryHint.Value.StartsWith("SENS-", StringComparison.Ordinal)
            ? request.CategoryHint
            : CategoryId.Parse(FallbackCategory);

        var payload = new MinimizedCandidate(
            CandidateId: request.CandidateId,
            CategoryHint: category,
            ContentKind: contentKind,
            Extension: extension,
            UntrustedContext: untrustedContext,
            RedactedCandidateValue: redactedValue,
            ContextLeftTruncatedBytes: leftTrunc,
            ContextRightTruncatedBytes: rightTrunc,
            ContextTruncated: leftTrunc > 0 || rightTrunc > 0,
            SecretRedactions: redactions,
            PackedUtf8ByteLength: 0);

        int packed = MeasurePacked(payload);
        if (packed <= CandidateByteBudget)
            return payload with { PackedUtf8ByteLength = packed };

        // Budget exceeded → shrink the context until the payload fits.
        int reservedForEnvelope = packed - Encoding.UTF8.GetByteCount(payload.UntrustedContext);
        int desiredContextBytes = Math.Max(0, CandidateByteBudget - reservedForEnvelope - MinContextReservation);
        string trimmed = TrimContextSymmetrically(
            payload.UntrustedContext, payload.UntrustedContext.Length / 2, desiredContextBytes);
        var shrunk = payload with { UntrustedContext = trimmed };
        return shrunk with { PackedUtf8ByteLength = MeasurePacked(shrunk) };
    }

    private static string ComputeRedactedCandidateValue(
        string candidateValue,
        string fullContext,
        SourceLocator locator,
        IReadOnlyList<DeterministicSecretSpan> spans)
    {
        if (string.IsNullOrEmpty(candidateValue) || spans.Count == 0)
            return candidateValue;

        var (charStart, charLen) = ResolveCharRange(locator, fullContext);
        if (charLen <= 0 || charStart < 0)
            return candidateValue;

        int candidateEnd = charStart + charLen;
        foreach (var span in spans)
        {
            int spanEnd = span.Start + span.Length;
            bool overlaps = span.Start < candidateEnd && charStart < spanEnd;
            if (!overlaps) continue;
            if (string.IsNullOrEmpty(span.Category)) continue;
            return $"[REDACTED:{span.Category}]";
        }
        return candidateValue;
    }

    private static (string Context, long LeftTruncated, long RightTruncated) CropAroundLocator(
        string maskedContext,
        string originalContext,
        SourceLocator locator)
    {
        if (maskedContext.Length == 0)
            return (string.Empty, 0L, 0L);

        var (charStart, charLen) = ResolveCharRange(locator, originalContext);
        if (charStart < 0 || charLen <= 0)
            return (maskedContext, 0L, 0L);

        int candidateCenter = Math.Min(maskedContext.Length, charStart + (charLen / 2));

        // Reserve ~1 KiB of headroom for the envelope outside the
        // context (candidate id, category hint, content kind, etc.).
        const int envelopeReserve = 1024;
        int contextByteBudget = CandidateByteBudget - envelopeReserve;
        if (contextByteBudget < MinContextReservation)
            contextByteBudget = MinContextReservation;

        // Start with a wide symmetric window and tighten until we
        // fit. Chars, not bytes — byte budget enforced via trimming.
        int sideChars = Math.Min(maskedContext.Length, Math.Max(8, contextByteBudget / 4));
        int left = Math.Max(0, candidateCenter - sideChars);
        int right = Math.Min(maskedContext.Length, candidateCenter + sideChars);

        string window = Slice(maskedContext, left, right);
        long leftTruncatedBytes = Encoding.UTF8.GetByteCount(maskedContext.AsSpan(0, left));
        long rightTruncatedBytes = Encoding.UTF8.GetByteCount(maskedContext.AsSpan(right));

        int bytes = Encoding.UTF8.GetByteCount(window);
        if (bytes <= contextByteBudget)
            return (window, leftTruncatedBytes, rightTruncatedBytes);

        int trimBytes = bytes - contextByteBudget;
        var (trimmed, extraLeft, extraRight) =
            TrimWindowSymmetrically(window, candidateCenter - left, trimBytes);
        return (trimmed, leftTruncatedBytes + extraLeft, rightTruncatedBytes + extraRight);
    }

    private static (string Context, long LeftTruncated, long RightTruncated) TrimWindowSymmetrically(
        string window, int candidateOffset, int bytesToTrim)
    {
        if (bytesToTrim <= 0 || window.Length == 0)
            return (window, 0L, 0L);

        // Approximate per-side UTF-8 byte budget, then trim a few
        // extra bytes to account for the imprecision.
        int perSide = (bytesToTrim + 1) / 2;
        int leftByte = Math.Max(0, Encoding.UTF8.GetByteCount(window.AsSpan(0, candidateOffset)) - perSide);
        int rightByte = Math.Min(Encoding.UTF8.GetByteCount(window), leftByte + 2 * perSide);

        int leftChar = ByteOffsetToCharOffset(window, leftByte);
        int rightChar = ByteOffsetToCharOffset(window, rightByte);

        while (leftChar > 0 && char.IsLowSurrogate(window[leftChar])) leftChar--;
        while (leftChar > 0 && char.IsHighSurrogate(window[leftChar - 1])) leftChar--;
        while (rightChar < window.Length && char.IsHighSurrogate(window[rightChar - 1])) rightChar++;
        while (rightChar < window.Length && char.IsLowSurrogate(window[rightChar])) rightChar++;

        if (rightChar <= leftChar)
            return (string.Empty, Encoding.UTF8.GetByteCount(window), 0L);

        long leftExtra = Encoding.UTF8.GetByteCount(window.AsSpan(0, leftChar));
        long rightExtra = Encoding.UTF8.GetByteCount(window.AsSpan(rightChar));
        return (window.Substring(leftChar, rightChar - leftChar), leftExtra, rightExtra);
    }

    private static string TrimContextSymmetrically(string text, int center, int desiredBytes)
    {
        if (desiredBytes <= 0) return string.Empty;
        if (Encoding.UTF8.GetByteCount(text) <= desiredBytes) return text;

        int perSideBytes = desiredBytes / 2;
        int leftByte = Math.Max(0, Encoding.UTF8.GetByteCount(text.AsSpan(0, center)) - perSideBytes);
        int rightByte = Math.Min(Encoding.UTF8.GetByteCount(text), leftByte + desiredBytes);

        int leftChar = ByteOffsetToCharOffset(text, leftByte);
        int rightChar = ByteOffsetToCharOffset(text, rightByte);

        while (leftChar > 0 && char.IsLowSurrogate(text[leftChar])) leftChar--;
        while (leftChar > 0 && char.IsHighSurrogate(text[leftChar - 1])) leftChar--;
        while (rightChar < text.Length && char.IsHighSurrogate(text[rightChar - 1])) rightChar++;
        while (rightChar < text.Length && char.IsLowSurrogate(text[rightChar])) rightChar++;

        if (rightChar <= leftChar) return string.Empty;
        return text.Substring(leftChar, rightChar - leftChar);
    }

    private static int ByteOffsetToCharOffset(string text, int byteOffset)
    {
        if (byteOffset <= 0) return 0;
        int b = 0;
        for (int i = 0; i < text.Length; i++)
        {
            int charBytes = Encoding.UTF8.GetByteCount(text.AsSpan(i, 1));
            if (b + charBytes > byteOffset) return i;
            b += charBytes;
            if (b == byteOffset) return i + 1;
        }
        return text.Length;
    }

    private static (int CharStart, int CharLen) ResolveCharRange(
        SourceLocator locator, string fullContext)
    {
        switch (locator)
        {
            case SourceLocator.TextLocator t:
                return MapByteRangeToCharRange(fullContext, t.ByteStart, t.ByteLength);
            case SourceLocator.JsonLocator j:
                return MapByteRangeToCharRange(fullContext, j.ByteStart, j.ByteLength);
            default:
                return (0, fullContext.Length);
        }
    }

    private static (int CharStart, int CharLen) MapByteRangeToCharRange(
        string text, long byteStart, long byteLength)
    {
        if (byteStart < 0 || byteLength <= 0)
            return (-1, 0);
        if (byteStart > int.MaxValue || byteLength > int.MaxValue)
            return (-1, 0);

        int target = (int)byteStart;
        int length = (int)byteLength;
        int b = 0;
        int startChar = -1;
        for (int i = 0; i < text.Length; i++)
        {
            int charBytes = Encoding.UTF8.GetByteCount(text.AsSpan(i, 1));
            if (b == target) { startChar = i; break; }
            if (b + charBytes > target) { startChar = i + 1; break; }
            b += charBytes;
        }
        if (startChar < 0) startChar = Math.Min(text.Length, Math.Max(0, target));
        int endChar = ByteOffsetToCharOffset(text, target + length);
        if (endChar <= startChar) endChar = Math.Min(text.Length, startChar + 1);
        return (startChar, endChar - startChar);
    }

    private static long CountSecretRedactions(string masked)
    {
        const string token = "[REDACTED:";
        long count = 0;
        int idx = 0;
        while ((idx = masked.IndexOf(token, idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += token.Length;
        }
        return count;
    }

    private static int MeasurePacked(MinimizedCandidate payload)
    {
        int ctxBytes = Encoding.UTF8.GetByteCount(payload.UntrustedContext);
        int valBytes = Encoding.UTF8.GetByteCount(payload.RedactedCandidateValue);
        int catBytes = Encoding.UTF8.GetByteCount(payload.CategoryHint.Value);
        int extBytes = Encoding.UTF8.GetByteCount(payload.Extension);
        int kindBytes = Encoding.UTF8.GetByteCount(payload.ContentKind);
        const int idBytes = 36;
        return idBytes + catBytes + extBytes + kindBytes + ctxBytes + valBytes + 256;
    }

    private static string Slice(string text, int start, int end)
    {
        while (start > 0 && char.IsLowSurrogate(text[start])) start++;
        while (end < text.Length && char.IsHighSurrogate(text[end - 1])) end--;
        if (end <= start) return string.Empty;
        return text.Substring(start, end - start);
    }

    private static string NormalizeContentKind(string kind)
    {
        if (string.IsNullOrWhiteSpace(kind)) return "text";
        return kind.ToLowerInvariant() switch
        {
            "text" => "text",
            "binary" => "binary",
            "archive" or "office" or "pdf" or "structured" or "image" => "archive",
            _ => "text",
        };
    }

    private static string NormalizeExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return string.Empty;
        string trimmed = extension.Trim().ToLowerInvariant();
        if (trimmed.Length > 16) trimmed = trimmed[..16];
        if (!trimmed.StartsWith('.')) trimmed = "." + trimmed;
        var sb = new StringBuilder(trimmed.Length);
        foreach (char c in trimmed)
        {
            if (c == '/' || c == '\\' || c == ':' || c == '\0') break;
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static string NormalizeUntrustedText(string value)
    {
        var builder = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsControl(c))
            {
                builder.Append(' ');
                continue;
            }

            if (c == '{' &&
                value.AsSpan(i).StartsWith("{\"name\":", StringComparison.OrdinalIgnoreCase))
            {
                builder.Append("{ \"name\":");
                i += "{\"name\":".Length - 1;
                continue;
            }

            builder.Append(c);
        }
        return builder.ToString();
    }
}
