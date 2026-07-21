using System.Text;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Replaces deterministic-detector-identified secret spans in a context
/// string with stable <c>[REDACTED:SENS-xxx]</c> tokens. The masker is
/// always applied before byte-limit cropping so the cropped window
/// already has secrets removed.
///
/// Invariants:
///   * Spans are validated against the input string; any zero-length,
///     negative, or out-of-bounds span is silently skipped.
///   * Overlapping spans are coalesced into a single redaction so the
///     original secret bytes never reappear in the output ("never
///     unmasks through overlap").
///   * The replacement token uses the leftmost span's category; later
///     overlapping spans never overwrite an already-redacted range.
/// </summary>
public sealed class DeterministicSecretMasker
{
    private const string RedactionPrefix = "[REDACTED:";

    /// <summary>
    /// Masks every secret span in <paramref name="text"/>. The returned
    /// string is guaranteed to be UTF-16 safe (no surrogate splits) and
    /// to never contain the original secret bytes that fall inside any
    /// span. Spans with identical categories share the same replacement
    /// token shape so downstream consumers cannot distinguish them.
    /// </summary>
    public static string Mask(string text, IReadOnlyList<DeterministicSecretSpan> spans)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(spans);

        if (spans.Count == 0 || text.Length == 0)
            return text;

        // 1. Filter + validate spans against the input string.
        var valid = new List<DeterministicSecretSpan>(spans.Count);
        foreach (var span in spans)
        {
            if (span.Length <= 0) continue;
            if (span.Start < 0) continue;
            if (span.Start >= text.Length) continue;
            if (span.Start + span.Length > text.Length) continue;
            if (string.IsNullOrEmpty(span.Category)) continue;
            valid.Add(span);
        }
        if (valid.Count == 0)
            return text;

        // 2. Sort by (Start asc, Length desc) so longer spans are
        //    visited first at the same starting position.
        valid.Sort(static (a, b) =>
        {
            int c = a.Start.CompareTo(b.Start);
            if (c != 0) return c;
            return b.Length.CompareTo(a.Length);
        });

        // 3. Coalesce overlapping/adjacent spans. The merged range is
        //    capped at the union end; the category is the leftmost
        //    span's category so the original secret bytes can never
        //    re-emerge from a different span overwriting the union.
        var coalesced = new List<(int Start, int End, string Category)>(valid.Count);
        foreach (var span in valid)
        {
            int end = span.Start + span.Length;
            if (coalesced.Count == 0)
            {
                coalesced.Add((span.Start, end, span.Category));
                continue;
            }
            var last = coalesced[^1];
            if (span.Start <= last.End)
            {
                // Overlapping or touching — extend the existing
                // coalesced range; keep the leftmost category.
                int newEnd = Math.Max(last.End, end);
                coalesced[^1] = (last.Start, newEnd, last.Category);
            }
            else
            {
                coalesced.Add((span.Start, end, span.Category));
            }
        }

        // 4. Build the output by stitching un-masked slices with
        //    redaction tokens. Validate surrogate boundaries at each
        //    splice to keep the output safe for System.Text.Json.
        var sb = new StringBuilder(text.Length);
        int cursor = 0;
        foreach (var (start, end, category) in coalesced)
        {
            if (start > cursor)
                AppendSlice(sb, text, cursor, start);
            sb.Append(RedactionPrefix);
            sb.Append(category);
            sb.Append(']');
            cursor = end;
        }
        if (cursor < text.Length)
            AppendSlice(sb, text, cursor, text.Length);
        return sb.ToString();
    }

    private static void AppendSlice(StringBuilder sb, string text, int start, int end)
    {
        // Trim the slice so it never starts or ends with an unpaired
        // surrogate — that would corrupt the JSON output.
        int sliceStart = start;
        int sliceEnd = end;
        if (sliceStart < sliceEnd && char.IsLowSurrogate(text[sliceStart]))
            sliceStart++;
        if (sliceEnd > sliceStart && char.IsHighSurrogate(text[sliceEnd - 1]))
            sliceEnd--;
        if (sliceStart >= sliceEnd) return;
        sb.Append(text, sliceStart, sliceEnd);
    }
}
