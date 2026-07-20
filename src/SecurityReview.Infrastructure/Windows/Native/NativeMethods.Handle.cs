using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Infrastructure.Windows.Native;

internal static partial class NativeMethods
{
    internal const uint GenericRead = 0x8000_0000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    // The duplicated handle value is only meaningful inside the target process,
    // so it is returned as a raw value and never wrapped or closed locally.
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DuplicateHandle(nint sourceProcess, SafeHandle sourceHandle,
        SafeHandle targetProcess, out nint targetHandle, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [LibraryImport("kernel32.dll")]
    internal static partial nint GetCurrentProcess();
}

internal class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeKernelHandle()
        : base(true)
    {
    }

    public SafeKernelHandle(nint handle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}

internal sealed class SafeJobHandle : SafeKernelHandle
{
    public SafeJobHandle()
    {
    }

    public SafeJobHandle(nint handle, bool ownsHandle)
        : base(handle, ownsHandle)
    {
    }
}
