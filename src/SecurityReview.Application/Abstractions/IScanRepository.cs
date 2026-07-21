using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for scan runs.
/// </summary>
public interface IScanRepository
{
    Task InsertAsync(ScanRun scan, CancellationToken cancellationToken = default);
    Task<ScanRun?> GetByIdAsync(ScanId scanId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScanRun>> ListAsync(CancellationToken cancellationToken = default);
    Task<bool> TryTransitionAsync(ScanId scanId, ScanStatus expectedStatus, long expectedVersion,
        ScanStatus nextStatus, CancellationToken cancellationToken = default);
    Task UpdateAsync(ScanRun scan, CancellationToken cancellationToken = default);
}
