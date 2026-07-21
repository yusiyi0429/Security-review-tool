using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

public sealed class WindowsFileHandleBroker : IFileHandleBroker
{
    public Task<long> DuplicateReadOnlyAsync(SafeFileHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(targetProcess);
        if (!NativeMethods.DuplicateHandle(NativeMethods.GetCurrentProcess(), source,
            targetProcess, out nint duplicated, NativeMethods.GenericRead,
            inheritHandle: false, options: 0))
        {
            throw new WindowsSecurityException("DuplicateHandle",
                Marshal.GetLastPInvokeError());
        }

        // The value belongs to the target process's handle table; it must never
        // be closed or used locally.
        return Task.FromResult((long)duplicated);
    }

    public Task<long> DuplicateReadOnlyAsync(IBrokeredReadHandle source, SafeHandle targetProcess,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (source is not SecurityReview.Infrastructure.Windows.Files.BrokeredReadHandle handle)
        {
            throw new WindowsSecurityException("BrokeredReadHandle", 6);
        }

        return DuplicateReadOnlyAsync(handle.Handle, targetProcess, cancellationToken);
    }
}
