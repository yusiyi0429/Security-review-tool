using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Application.Abstractions;

public interface IFileHandleBroker
{
    // Duplicates a file handle into the target process with read-only access and
    // returns the handle value that is valid inside the target process.
    Task<long> DuplicateReadOnlyAsync(SafeFileHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken);
}
