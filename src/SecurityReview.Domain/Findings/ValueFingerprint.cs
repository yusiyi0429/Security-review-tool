namespace SecurityReview.Domain.Findings;

/// <summary>
/// An opaque, keyed fingerprint of a normalized finding value, suitable for
/// privacy-preserving cross-scan deduplication and grouping. The fingerprint
/// is computed via HMAC-SHA256 keyed with a per-process or per-user secret;
/// a raw SHA-256 digest of the value must never be stored.
/// </summary>
public readonly record struct ValueFingerprint(string HexString);
