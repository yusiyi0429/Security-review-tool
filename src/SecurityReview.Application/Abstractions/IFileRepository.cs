using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Encrypted persistence for file records.
/// </summary>
public interface IFileRepository
{
    Task InsertAsync(ScanId scanId, FileRecord file, CancellationToken cancellationToken = default);
    Task InsertBatchAsync(ScanId scanId, IReadOnlyList<FileRecord> files, CancellationToken cancellationToken = default);
    Task<FileRecord?> GetByIdAsync(FileId fileId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default);
    Task<int> CountByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default);
}
