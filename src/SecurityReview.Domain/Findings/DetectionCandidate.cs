using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Domain.Rules;

namespace SecurityReview.Domain.Findings;

/// <summary>
/// A bounded detection match that a detector produces for a single chunk.
///
/// Value and context are length-capped at 5,000 UTF-16 code units each.
/// Oversized logical matches are not silently truncated: the factory emits a
/// <c>candidate_match_over_limit</c> marker with the original source range and
/// a keyed HMAC-SHA256 of the full value (never a raw isolated-value hash),
/// then marks that region as partially covered.
/// </summary>
public sealed record DetectionCandidate
{
    public const int MaxValueLength = 5_000;
    public const int MaxContextLength = 5_000;
    public const int MinValueLength = 1;

    public CandidateId Id { get; init; }
    public string Value { get; init; } = string.Empty;
    public string Context { get; init; } = string.Empty;
    public SourceLocator Locator { get; init; } = new SourceLocator.TextLocator(0, 0, 0, 0);

    /// <summary>The rule that triggered this candidate.</summary>
    public RuleId RuleId { get; init; }

    /// <summary>The detector that found the match.</summary>
    public DetectorId DetectorId { get; init; }

    public Severity Severity { get; init; }
    public DetectionConfidence Confidence { get; init; }
    public bool RequiresSemanticReview { get; init; }
    public FindingKind FindingKind { get; init; }

    /// <summary>
    /// True when the original match value exceeded <see cref="MaxValueLength"/>
    /// and this candidate carries a truncated/hmac-based representation.
    /// </summary>
    public bool IsOverLimit { get; init; }

    /// <summary>
    /// When <see cref="IsOverLimit"/> is true, the HMAC-SHA256 of the full
    /// original value keyed with a per-session secret (hex-encoded, 64 chars).
    /// </summary>
    public string? ValueHmac { get; init; }

    /// <summary>
    /// Create a standard (non-oversized) candidate.
    /// </summary>
    public static DetectionCandidate Create(
        string value,
        string context,
        SourceLocator locator,
        RuleId ruleId,
        DetectorId detectorId,
        Severity severity,
        DetectionConfidence confidence,
        FindingKind findingKind,
        bool requiresSemanticReview = false)
    {
        ValidateValue(value);
        ValidateContext(context);
        ValidateNoUnpairedSurrogate(value);
        ValidateNoUnpairedSurrogate(context);

        return new DetectionCandidate
        {
            Id = new CandidateId(Guid.NewGuid()),
            Value = Truncate(value, MaxValueLength),
            Context = Truncate(context, MaxContextLength),
            Locator = locator,
            RuleId = ruleId,
            DetectorId = detectorId,
            Severity = severity,
            Confidence = confidence,
            RequiresSemanticReview = requiresSemanticReview,
            FindingKind = findingKind,
            IsOverLimit = false
        };
    }

    /// <summary>
    /// Create an over-limit candidate when the matched value exceeds
    /// <see cref="MaxValueLength"/>. The value is truncated, and a keyed
    /// HMAC-SHA256 of the full original value is stored for audit correlation.
    /// The region covered by this candidate is marked as partially covered.
    /// </summary>
    public static DetectionCandidate CreateOverLimit(
        string fullValue,
        string context,
        SourceLocator locator,
        RuleId ruleId,
        DetectorId detectorId,
        Severity severity,
        DetectionConfidence confidence,
        FindingKind findingKind,
        ReadOnlySpan<byte> hmacKey,
        bool requiresSemanticReview = false)
    {
        ArgumentOutOfRangeException.ThrowIfZero(hmacKey.Length);

        ValidateContext(context);
        ValidateNoUnpairedSurrogate(context);

        string truncated = Truncate(fullValue, MaxValueLength);
        string hmac = ComputeKeyedHmac(fullValue, hmacKey);

        return new DetectionCandidate
        {
            Id = new CandidateId(Guid.NewGuid()),
            Value = truncated,
            Context = Truncate(context, MaxContextLength),
            Locator = locator,
            RuleId = ruleId,
            DetectorId = detectorId,
            Severity = severity,
            Confidence = confidence,
            RequiresSemanticReview = requiresSemanticReview,
            FindingKind = findingKind,
            IsOverLimit = true,
            ValueHmac = hmac
        };
    }

    private static void ValidateValue(string value)
    {
        if (value.Length < MinValueLength)
            throw new ArgumentException("Candidate value must be at least 1 character.", nameof(value));
    }

    private static void ValidateContext(string context)
    {
        ArgumentNullException.ThrowIfNull(context);
    }

    private static void ValidateNoUnpairedSurrogate(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                    throw new ArgumentException("Value contains an unpaired high surrogate.", nameof(value));
                i++;
            }
            else if (char.IsLowSurrogate(value[i]))
            {
                throw new ArgumentException("Value contains an unpaired low surrogate.", nameof(value));
            }
        }
    }

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength) return value;

        // Ensure we don't split a surrogate pair at the boundary
        int cut = maxLength;
        if (cut > 0 && char.IsHighSurrogate(value[cut - 1]))
            cut--;

        return value[..cut];
    }

    private static string ComputeKeyedHmac(string value, ReadOnlySpan<byte> key)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(value.Length));
        try
        {
            int byteCount = Encoding.UTF8.GetBytes(value, rented);
            byte[] hash = HMACSHA256.HashData(key, rented.AsSpan(0, byteCount));
            return Convert.ToHexStringLower(hash);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public string DedupKey(JobId jobId, string virtualPath)
    {
        // Dedup key: file ID + virtual path + source locator + rule ID + detector ID
        return $"{jobId.Value:N}|{virtualPath}|{Locator.ToCanonicalDisplay()}|{RuleId.Value}|{DetectorId.Value}";
    }

    /// <summary>
    /// Serialized "完整命中值" must stay below Excel's 32,767-character cell limit.
    /// With the 5,000-code-unit cap, worst-case six-character JSON escaping
    /// (e.g. "\uXXXX" = 6 chars per code unit) stays under 30,006 chars, leaving
    /// room for the JSON structural overhead.
    /// </summary>
    public static int MaxSerializedValueLength => MaxValueLength * 6;
}
