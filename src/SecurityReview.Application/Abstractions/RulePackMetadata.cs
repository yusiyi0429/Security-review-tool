using SecurityReview.Domain.Rules;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Read-only projection of a rule pack row from the rule_packs table.
/// All columns are searchable; no encrypted payload.
/// </summary>
public readonly record struct RulePackMetadata(
    string RulePackHash,
    string RulePackId,
    string Version,
    string SignerId,
    string PackagePathHmac,
    DateTimeOffset ImportedAtUtc,
    RulePackStatus Status);
