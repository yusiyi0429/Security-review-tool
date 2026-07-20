using System.Runtime.InteropServices;

namespace SecurityReview.Infrastructure.Windows.Native;

internal static partial class NativeMethods
{
    internal const uint CreateSuspended = 0x0000_0004;
    internal const uint CreateUnicodeEnvironment = 0x0000_0400;
    internal const uint ExtendedStartupInfoPresent = 0x0008_0000;
    internal const uint CreateNoWindow = 0x0800_0000;
    internal const nuint ProcThreadAttributeSecurityCapabilities = 0x0002_0009;
    internal const uint TokenQuery = 0x0008;
    internal const uint TokenAppContainerSid = 31;
    internal const uint WaitObject0 = 0;
    internal const uint StillActive = 259;

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoW
    {
        public uint cb;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort cbReserved2;
        public nint Reserved2;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoExW
    {
        public StartupInfoW StartupInfo;
        public nint AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityCapabilities
    {
        public nint AppContainerSid;
        public nint Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateProcessW",
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcess(string? applicationName, Span<char> commandLine,
        nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags,
        nint environment, string? currentDirectory, ref StartupInfoExW startupInfo,
        out ProcessInformation processInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool InitializeProcThreadAttributeList(nint attributeList,
        uint attributeCount, nuint flags, ref nuint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UpdateProcThreadAttribute(nint attributeList, nuint flags,
        nuint attribute, ref SecurityCapabilities value, nuint size, nint previousValue,
        nint returnSize);

    [LibraryImport("kernel32.dll")]
    internal static partial void DeleteProcThreadAttributeList(nint attributeList);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int ResumeThread(SafeHandle thread);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(SafeHandle process, uint desiredAccess,
        out nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(SafeHandle token, uint informationClass,
        nint information, uint informationLength, out uint returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint WaitForSingleObject(SafeHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateProcess(SafeHandle process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetExitCodeProcess(SafeHandle process, out uint exitCode);
}
