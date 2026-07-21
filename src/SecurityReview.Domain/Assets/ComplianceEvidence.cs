namespace SecurityReview.Domain.Assets;

public enum ComplianceEvidenceStatus
{
    Verified,
    DeclaredWithoutReference,
    NotApplicable,
    Unverifiable
}

// A declaration is attestation only: it carries a status plus an optional
// external reference and deliberately has no member that could downgrade or
// skip content scanning.
public sealed record ComplianceDeclaration(ComplianceEvidenceStatus Status, string? Reference)
{
    public static ComplianceDeclaration Parse(string status, string? reference) =>
        new(ParseStatus(status), reference);

    public static ComplianceEvidenceStatus ParseStatus(string status) => status switch
    {
        "verified" => ComplianceEvidenceStatus.Verified,
        "declared_without_reference" => ComplianceEvidenceStatus.DeclaredWithoutReference,
        "not_applicable" => ComplianceEvidenceStatus.NotApplicable,
        "unverifiable" => ComplianceEvidenceStatus.Unverifiable,
        _ => throw new ArgumentException("Unknown compliance evidence status.", nameof(status))
    };

    public static string ToToken(ComplianceEvidenceStatus status) => status switch
    {
        ComplianceEvidenceStatus.Verified => "verified",
        ComplianceEvidenceStatus.DeclaredWithoutReference => "declared_without_reference",
        ComplianceEvidenceStatus.NotApplicable => "not_applicable",
        ComplianceEvidenceStatus.Unverifiable => "unverifiable",
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown status.")
    };
}

public sealed record ThirdPartyAuthorization(string Name, ComplianceDeclaration Declaration);

public sealed record ComplianceEvidence(
    ComplianceDeclaration KnowledgeBaseTransformed,
    ComplianceDeclaration ModelFinetuned,
    IReadOnlyList<ThirdPartyAuthorization> ThirdPartyAuthorizations)
{
    public const int MaxThirdPartyAuthorizations = 1_000;

    public static ComplianceEvidence Create(
        ComplianceDeclaration knowledgeBaseTransformed,
        ComplianceDeclaration modelFinetuned,
        IReadOnlyList<ThirdPartyAuthorization> thirdPartyAuthorizations)
    {
        ArgumentNullException.ThrowIfNull(knowledgeBaseTransformed);
        ArgumentNullException.ThrowIfNull(modelFinetuned);
        ArgumentNullException.ThrowIfNull(thirdPartyAuthorizations);
        if (thirdPartyAuthorizations.Count > MaxThirdPartyAuthorizations)
        {
            throw new ArgumentException(
                "Manifest must declare at most 1,000 third-party authorizations.",
                nameof(thirdPartyAuthorizations));
        }

        if (thirdPartyAuthorizations.Any(x => string.IsNullOrWhiteSpace(x.Name)))
        {
            throw new ArgumentException(
                "Third-party authorizations require a non-empty name.",
                nameof(thirdPartyAuthorizations));
        }

        return new(knowledgeBaseTransformed, modelFinetuned, thirdPartyAuthorizations);
    }
}
