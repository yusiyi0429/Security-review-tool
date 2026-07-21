using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Application.Scans.Inventory;

namespace SecurityReview.Application.Abstractions;

public interface IFileHandleBroker
{
    // Duplicates a file handle into the target process with read-only access and
    // returns the handle value that is valid inside the target process.
    Task<long> DuplicateReadOnlyAsync(SafeFileHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken);

    // Same, but takes an opaque broker handle that already owns its SafeFileHandle.
    // Only Infrastructure can extract the raw handle from the broker.
    Task<long> DuplicateReadOnlyAsync(IBrokeredReadHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken);
}
