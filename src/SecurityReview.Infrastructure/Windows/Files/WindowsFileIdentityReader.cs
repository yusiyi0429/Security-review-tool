using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Infrastructure.Windows.Files;

internal static partial class InventoryNative
{
    internal const uint FileFlagOpenReparsePoint = 0x0020_0000;
    internal const uint FileFlagBackupSemantics = 0x0200_0000;
    internal const uint OpenExisting = 3;
    internal const uint FileShareAll = 0x0000_0007;
    internal const int FileAttributeTagInfoClass = 9;
    internal const int FileIdInfoClass = 18;

    // Opens a file or directory for metadata queries only (zero desired
    // access), never following the reparse target.
    internal static SafeFileHandle OpenForIdentity(string fullPath)
    {
        SafeFileHandle handle = CreateFile(ToExtendedPath(fullPath), 0,
            FileShareAll, nint.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics, nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new WindowsSecurityException("CreateFileW", error);
        }

        return handle;
    }

    internal static string ToExtendedPath(string fullPath)
    {
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return fullPath;
        }

        return fullPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + fullPath[2..]
            : @"\\?\" + fullPath;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateFileW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(string fileName, uint desiredAccess,
        uint shareMode, nint securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, nint templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandleEx(SafeFileHandle file,
        int informationClass, nint information, uint bufferSize);

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "GetVolumeInformationW",
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetVolumeInformation(string rootPathName,
        nint volumeNameBuffer, uint volumeNameSize, nint volumeSerialNumber,
        nint maximumComponentLength, nint fileSystemFlags, nint fileSystemNameBuffer,
        uint fileSystemNameSize);
}

// Reads the stable (volume serial, 128-bit file index) identity of a file
// without opening its data and without following reparse points.
public sealed class WindowsFileIdentityReader
{
#pragma warning disable CA1822 // Helper is intentionally a class for future extension (cached identity, inotify-equivalent watchers); the instance shape is not premature.
    public FileStreamIdentity Read(string fullPath, string? streamName = null)
    {
        using SafeFileHandle handle = InventoryNative.OpenForIdentity(fullPath);
        nint buffer = Marshal.AllocHGlobal(24);
        try
        {
            if (!InventoryNative.GetFileInformationByHandleEx(handle,
                InventoryNative.FileIdInfoClass, buffer, 24))
            {
                throw new WindowsSecurityException("GetFileInformationByHandleEx",
                    Marshal.GetLastPInvokeError());
            }

            long volumeSerial = Marshal.ReadInt64(buffer);
            ulong lo = (ulong)Marshal.ReadInt64(buffer + 8);
            ulong hi = (ulong)Marshal.ReadInt64(buffer + 16);
            var fileIndex = new UInt128(hi, lo);
            return new FileStreamIdentity(
                volumeSerial.ToString("X16", System.Globalization.CultureInfo.InvariantCulture),
                fileIndex, streamName);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
