using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans.Inventory;

// Application-level opaque wrapper for a read-only file handle. The raw
// SafeFileHandle stays in Infrastructure; only the typed boundary crosses.
public interface IBrokeredReadHandle : IDisposable
{
    FileSnapshot InitialSnapshot { get; }
    string DisplayId { get; }
}

public interface IFileSnapshotService
{
    // Opens the file/stream at scanRootPath, reads identity + length + sha256,
    // and closes the read-only handle. The returned snapshot is the authoritative
    // pre-parse view; subsequent mutations become stability decisions.
    Task<FileSnapshot> OpenAndHashAsync(string scanRootPath, FileRecord file,
        CancellationToken cancellationToken);
}
