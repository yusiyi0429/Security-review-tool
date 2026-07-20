using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Infrastructure.Windows.Native;

internal static partial class NativeMethods
{
    internal const uint SeFileObject = 1;
    internal const uint DaclSecurityInformation = 0x0000_0004;
    internal const uint SetAccess = 1;
    internal const uint TrusteeIsSid = 0;
    internal const uint TrusteeIsUnknown = 0;
    internal const uint ContainerAndObjectInherit = 0x3;
    internal const uint NoInheritance = 0;
    internal const uint GenericReadExecute = 0xA000_0000; // GENERIC_READ | GENERIC_EXECUTE
    internal const int ErrorAlreadyExistsUnchecked = unchecked((int)0x8007_00B7);

    [LibraryImport("userenv.dll", EntryPoint = "CreateAppContainerProfile",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int CreateAppContainerProfile(string name, string displayName,
        string description, nint capabilities, uint capabilityCount, out nint appContainerSid);

    [LibraryImport("userenv.dll", EntryPoint = "DeriveAppContainerSidFromAppContainerName",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int DeriveAppContainerSidFromAppContainerName(string name,
        out nint appContainerSid);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertSidToStringSid(nint sid, out nint stringSid);

    [LibraryImport("advapi32.dll")]
    internal static partial nint FreeSid(nint sid);

    [LibraryImport("kernel32.dll")]
    internal static partial nint LocalFree(nint hMem);

    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint GetNamedSecurityInfo(string objectName, uint objectType,
        uint securityInfo, nint ownerSid, nint groupSid, out nint dacl, nint sacl,
        out nint securityDescriptor);

    [LibraryImport("advapi32.dll", EntryPoint = "SetEntriesInAclW")]
    internal static partial uint SetEntriesInAcl(uint countOfExplicitEntries,
        ref ExplicitAccess explicitAccess, nint oldAcl, out nint newAcl);

    [LibraryImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint SetNamedSecurityInfo(string objectName, uint objectType,
        uint securityInfo, nint ownerSid, nint groupSid, nint dacl, nint sacl);

    [StructLayout(LayoutKind.Sequential)]
    internal struct Trustee
    {
        public nint MultipleTrustee;
        public uint MultipleTrusteeOperation;
        public uint TrusteeForm;
        public uint TrusteeType;
        public nint TrusteeName; // PSID when TrusteeForm == TRUSTEE_IS_SID
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExplicitAccess
    {
        public uint AccessPermissions;
        public uint AccessMode;
        public uint Inheritance;
        public Trustee Trustee;
    }
}

internal sealed class SafeAppContainerSidHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeAppContainerSidHandle()
        : base(true)
    {
    }

    public SafeAppContainerSidHandle(nint handle)
        : base(true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.FreeSid(handle);
        return true;
    }
}
