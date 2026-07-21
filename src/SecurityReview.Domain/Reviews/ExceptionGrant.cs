namespace SecurityReview.Domain.Reviews;

/// <summary>
/// A time-bounded exception grant that exempts an exact finding binding from
/// review. The grant is valid only while <see cref="ValidUntilUtc"/> has not
/// passed and the binding fields match exactly.
///
/// Changing any field in the binding, the rule pack hash, or the rule ID
/// invalidates the grant. Changing severity without altering the rule/hash
/// does not broaden scope. There is no wildcard or global exception API.
/// </summary>
public sealed record ExceptionGrant(
    ExceptionGrantId Id,
    ExceptionBinding Binding,
    string RulePackHash,
    DateTimeOffset ValidUntilUtc,
    DateTimeOffset CreatedAtUtc,
    string UserSidHmac,
    string EncryptedReason)
{
    /// <summary>
    /// Create a validated exception grant with a mandatory expiry in the future.
    /// </summary>
    public static ExceptionGrant Create(
        ExceptionBinding binding,
        string rulePackHash,
        DateTimeOffset validUntilUtc,
        string userSidHmac,
        string encryptedReason)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(userSidHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedReason);

        if (validUntilUtc <= DateTimeOffset.UtcNow)
            throw new ArgumentException(
                "Exception grant expiry must be in the future.", nameof(validUntilUtc));

        return new ExceptionGrant(
            new ExceptionGrantId(Guid.NewGuid()),
            binding,
            rulePackHash,
            validUntilUtc,
            DateTimeOffset.UtcNow,
            userSidHmac,
            encryptedReason);
    }

    /// <summary>
    /// True while the grant has not yet expired.
    /// </summary>
    public bool IsActive(DateTimeOffset atUtc) => atUtc < ValidUntilUtc;
}
