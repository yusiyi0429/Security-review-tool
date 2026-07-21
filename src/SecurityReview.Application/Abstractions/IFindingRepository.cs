using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for finding groups and occurrences.
/// Finding groups have no encrypted payload (all columns are searchable).
/// Finding occurrences have an encrypted payload for raw values and locators.
/// </summary>
public interface IFindingRepository
{
    Task InsertGroupAsync(ScanId scanId, FindingGroup group, CancellationToken cancellationToken = default);
    Task InsertOccurrenceAsync(FileId fileId, FindingOccurrence occurrence, CancellationToken cancellationToken = default);
    Task InsertOccurrenceBatchAsync(FileId fileId, IReadOnlyList<FindingOccurrence> occurrences,
        CancellationToken cancellationToken = default);
    Task<FindingGroup?> GetGroupByIdAsync(FindingGroupId id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<FindingGroup>> GetGroupsByScanIdAsync(ScanId scanId,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesByGroupIdAsync(FindingGroupId groupId,
        CancellationToken cancellationToken = default);
}
