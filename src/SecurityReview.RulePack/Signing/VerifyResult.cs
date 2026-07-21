namespace SecurityReview.RulePack.Signing;

/// <summary>
/// Result of a rule-pack signature verification.
/// </summary>
public readonly record struct VerifyResult(bool IsValid, string ErrorCode);
