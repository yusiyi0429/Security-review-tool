namespace SecurityReview.Domain.Reviews;

/// <summary>
/// An exact, non-wildcard binding that identifies which finding an exception
/// grant covers. Every field contributes to the binding HMAC; changing any
/// single field invalidates the grant.
///
/// No wildcard, glob, or global exception API exists — each grant binds to
/// exactly one asset/version, file path, locator, value, rule pack hash,
/// and rule ID.
/// </summary>
public sealed record ExceptionBinding(
    string AssetIdHmac,
    string AssetVersionHmac,
    string FilePathHmac,
    string CanonicalLocatorHmac,
    string ValueHmac,
    string RulePackHash,
    string RuleId)
{
    /// <summary>
    /// Create a validated exception binding. All HMAC fields and identifiers
    /// must be non-empty.
    /// </summary>
    public static ExceptionBinding Create(
        string assetIdHmac,
        string assetVersionHmac,
        string filePathHmac,
        string canonicalLocatorHmac,
        string valueHmac,
        string rulePackHash,
        string ruleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(assetIdHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(assetVersionHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePathHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalLocatorHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(valueHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);

        return new ExceptionBinding(
            assetIdHmac,
            assetVersionHmac,
            filePathHmac,
            canonicalLocatorHmac,
            valueHmac,
            rulePackHash,
            ruleId);
    }
}
