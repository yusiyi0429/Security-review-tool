using SecurityReview.Domain.Rules;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Persistence for rule pack metadata. No encrypted payload — all columns
/// are searchable (hashes, IDs, status enums).
/// </summary>
public interface IRulePackMetadataRepository
{
    Task InsertAsync(string rulePackHash, string rulePackId, string version, string signerId,
        string packagePathHmac, RulePackStatus status, CancellationToken cancellationToken = default);
    Task<RulePackMetadata?> GetByHashAsync(string rulePackHash, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RulePackMetadata>> ListAsync(CancellationToken cancellationToken = default);
    Task UpdateStatusAsync(string rulePackHash, RulePackStatus status,
        CancellationToken cancellationToken = default);
}
