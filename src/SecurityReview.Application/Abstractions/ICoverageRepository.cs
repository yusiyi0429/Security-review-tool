using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for coverage gaps.
/// </summary>
public interface ICoverageRepository
{
    Task InsertAsync(CoverageGap gap, CancellationToken cancellationToken = default);
    Task InsertBatchAsync(IReadOnlyList<CoverageGap> gaps, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CoverageGap>> GetByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default);
}
