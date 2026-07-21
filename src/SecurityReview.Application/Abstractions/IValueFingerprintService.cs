using SecurityReview.Domain.Findings;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Computes a keyed, privacy-preserving fingerprint for a normalized finding
/// value, suitable for grouping across chunks and scans without storing the
/// raw value or any raw SHA-256 digest of it.
/// </summary>
public interface IValueFingerprintService
{
    ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue);
}
