using System.Runtime.Versioning;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Windows.Files;

// Opens a read-only file via WindowsReadOnlyFileBroker, captures the initial
// snapshot, and closes the handle. The returned snapshot is the authoritative
// pre-parse view used by the orchestration layer for stability decisions.
[SupportedOSPlatform("windows")]
public sealed class WindowsFileSnapshotService : IFileSnapshotService
{
    private readonly WindowsReadOnlyFileBroker _broker;

    public WindowsFileSnapshotService(WindowsReadOnlyFileBroker? broker = null)
    {
        _broker = broker ?? new WindowsReadOnlyFileBroker();
    }

    public async Task<FileSnapshot> OpenAndHashAsync(string scanRootPath, FileRecord file,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(scanRootPath);
        ArgumentNullException.ThrowIfNull(file);

        // The snapshot service reads, then closes — it never duplicates the
        // handle into a worker. The broker's internal helper handles retry and
        // handle lifecycle.
        return await _broker.OpenAndSnapshotAsync(scanRootPath, file, cancellationToken)
            .ConfigureAwait(false);
    }
}
