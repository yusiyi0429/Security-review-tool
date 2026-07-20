using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Infrastructure.Windows.Native;

internal static partial class NativeMethods
{
    internal const uint PipeAccessDuplex = 0x0000_0003;
    internal const uint FileFlagFirstPipeInstance = 0x0008_0000;
    internal const uint FileFlagOverlapped = 0x4000_0000;
    internal const uint PipeTypeByte = 0x0000_0000;
    internal const uint PipeReadmodeByte = 0x0000_0000;
    internal const uint PipeWait = 0x0000_0000;
    internal const uint PipeRejectRemoteClients = 0x0000_0008;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        public uint Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }

    // Returns INVALID_HANDLE_VALUE (-1) on failure; the caller wraps it.
    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateNamedPipeW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial nint CreateNamedPipe(string name, uint openMode, uint pipeMode,
        uint maxInstances, uint outBufferSize, uint inBufferSize, uint defaultTimeOut,
        ref SecurityAttributes securityAttributes);

    [LibraryImport("advapi32.dll", SetLastError = true,
        EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor, uint sddlRevision, out nint securityDescriptor,
        nint securityDescriptorSize);
}

internal sealed class SafeSecurityDescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeSecurityDescriptorHandle(nint handle)
        : base(true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.LocalFree(handle);
        return true;
    }
}
