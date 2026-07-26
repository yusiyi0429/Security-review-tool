using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Persists a new scan and its immutable configuration snapshot as one
/// transaction. A scan must never become visible without its snapshot.
/// </summary>
public interface IScanCreationRepository
{
    Task InsertAsync(
        ScanRun scan,
        ScanSnapshotRecord snapshot,
        CancellationToken cancellationToken = default);
}
