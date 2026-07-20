using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

public sealed record AppContainerProfileInfo(string SidString, bool Created);

public sealed class AppContainerProfile
{
    public const string ProfileName = "Company.SecurityReviewTool.Parser.V1";

    private static readonly ConcurrentDictionary<string, AppContainerProfileInfo> Ensured =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly string _profileName;

    public AppContainerProfile(string profileName = ProfileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(profileName);
        _profileName = profileName;
    }

    // Ensures the stable per-user AppContainer profile exists and grants its SID
    // read/execute on the (already hash-verified) worker staging directory only.
    // It never grants the SID access to a scan root or to the tool data directory.
    public Task<AppContainerProfileInfo> EnsureAsync(string workerStagingDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(workerStagingDirectory);
        string key = _profileName + "|" + workerStagingDirectory;
        return Task.Run(() => Ensured.GetOrAdd(key, _ => EnsureCore(workerStagingDirectory)),
            cancellationToken);
    }

    private AppContainerProfileInfo EnsureCore(string workerStagingDirectory)
    {
        string fullPath = Path.GetFullPath(workerStagingDirectory);
        if (!Directory.Exists(fullPath))
        {
            throw new WindowsSecurityException("GetFullPath", 2);
        }

        // The OS reclaims unused AppContainer profiles asynchronously; an
        // already-exists answer is only trusted while the mapping is present.
        string sidString = DeriveSidString();
        bool created = false;
        if (!ProfileMappingExists(sidString))
        {
            created = CreateProfile();
            if (!ProfileMappingExists(sidString))
            {
                throw new WindowsSecurityException("CreateAppContainerProfile",
                    0x8007_0002);
            }
        }

        GrantReadExecute(fullPath);
        return new AppContainerProfileInfo(sidString, created);
    }

    private bool CreateProfile()
    {
        int hr = NativeMethods.CreateAppContainerProfile(_profileName, _profileName,
            _profileName, nint.Zero, 0, out nint sid);
        if (hr == 0)
        {
            NativeMethods.FreeSid(sid);
            return true;
        }

        if (hr == NativeMethods.ErrorAlreadyExistsUnchecked)
        {
            return false;
        }

        throw new WindowsSecurityException("CreateAppContainerProfile", hr);
    }

    // Drops the cached ensure so the next call re-verifies and re-creates the
    // profile. Used when a launch observes that the OS reclaimed the profile.
    public void Invalidate(string workerStagingDirectory)
    {
        Ensured.TryRemove(_profileName + "|" + workerStagingDirectory,
            out _);
    }

    private static bool ProfileMappingExists(string sidString)
    {
        using Microsoft.Win32.RegistryKey? key = Microsoft.Win32.Registry.CurrentUser
            .OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows"
                + @"\CurrentVersion\AppContainer\Mappings\" + sidString,
                writable: false);
        return key is not null;
    }

    private string DeriveSidString()
    {
        using SafeAppContainerSidHandle sid = DeriveSid();
        return SidToString(sid);
    }

    private SafeAppContainerSidHandle DeriveSid()
    {
        int hr = NativeMethods.DeriveAppContainerSidFromAppContainerName(_profileName,
            out nint sid);
        if (hr != 0)
        {
            throw new WindowsSecurityException("DeriveAppContainerSidFromAppContainerName", hr);
        }

        return new SafeAppContainerSidHandle(sid);
    }

    internal static string SidToString(SafeHandle sid)
    {
        if (!NativeMethods.ConvertSidToStringSid(sid.DangerousGetHandle(), out nint native))
        {
            throw new WindowsSecurityException("ConvertSidToStringSidW",
                Marshal.GetLastPInvokeError());
        }

        try
        {
            return Marshal.PtrToStringUni(native)
                ?? throw new WindowsSecurityException("ConvertSidToStringSidW", 0);
        }
        finally
        {
            NativeMethods.LocalFree(native);
        }
    }

    private void GrantReadExecute(string path)
    {
        using SafeAppContainerSidHandle sid = DeriveSid();
        foreach (string entry in EnumerateSelfAndChildren(path))
        {
            uint inheritance = Directory.Exists(entry)
                ? NativeMethods.ContainerAndObjectInherit
                : NativeMethods.NoInheritance;
            AddAce(entry, sid, inheritance);
        }
    }

    private static IEnumerable<string> EnumerateSelfAndChildren(string root)
    {
        yield return root;
        foreach (string entry in Directory.EnumerateFileSystemEntries(root, "*",
            SearchOption.AllDirectories))
        {
            yield return entry;
        }
    }

    private static void AddAce(string path, SafeHandle sid, uint inheritance)
    {
        uint result = NativeMethods.GetNamedSecurityInfo(path, NativeMethods.SeFileObject,
            NativeMethods.DaclSecurityInformation, nint.Zero, nint.Zero, out nint dacl,
            nint.Zero, out nint securityDescriptor);
        if (result != 0)
        {
            throw new WindowsSecurityException("GetNamedSecurityInfoW", result);
        }

        nint newAcl = nint.Zero;
        try
        {
            var access = new NativeMethods.ExplicitAccess
            {
                AccessPermissions = NativeMethods.GenericReadExecute,
                AccessMode = NativeMethods.SetAccess,
                Inheritance = inheritance,
                Trustee = new NativeMethods.Trustee
                {
                    MultipleTrustee = nint.Zero,
                    MultipleTrusteeOperation = 0,
                    TrusteeForm = NativeMethods.TrusteeIsSid,
                    TrusteeType = NativeMethods.TrusteeIsUnknown,
                    TrusteeName = sid.DangerousGetHandle(),
                },
            };
            result = NativeMethods.SetEntriesInAcl(1, ref access, dacl, out newAcl);
            if (result != 0)
            {
                throw new WindowsSecurityException("SetEntriesInAclW", result);
            }

            result = NativeMethods.SetNamedSecurityInfo(path, NativeMethods.SeFileObject,
                NativeMethods.DaclSecurityInformation, nint.Zero, nint.Zero, newAcl, nint.Zero);
            if (result != 0)
            {
                throw new WindowsSecurityException("SetNamedSecurityInfoW", result);
            }
        }
        finally
        {
            if (newAcl != nint.Zero)
            {
                NativeMethods.LocalFree(newAcl);
            }

            NativeMethods.LocalFree(securityDescriptor);
        }
    }
}
