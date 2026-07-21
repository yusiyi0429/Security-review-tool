using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Signing;

namespace SecurityReview.RulePack.Validation;

/// <summary>
/// Validates a rule pack ZIP byte-for-byte before storage.
/// Validation order: ZIP limits → manifest schema → entry allowlist →
/// size/hash → signer key → ECDSA → client/version → graph/safety → summary.
/// </summary>
public interface IRulePackValidator
{
    ValidationSummary Validate(
        byte[] zipBytes,
        TrustedSignerStore signerStore,
        string appVersion);
}

/// <summary>
/// Complete result of a rule pack validation.
/// </summary>
public sealed record ValidationSummary
{
    public bool IsValid { get; init; }
    public string? ErrorCode { get; init; }
    public RulePackManifest? Manifest { get; init; }
    public RulePackDocument? Document { get; init; }
    public string PackageSha256 { get; init; } = "";
}
