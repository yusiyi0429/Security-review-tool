using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Infrastructure.Windows.Files;

// Inspects a reparse point's tag without ever following its target.
public sealed class ReparsePointInspector
{
#pragma warning disable CA1822 // Helper is intentionally a class for future extension (NtQueryReparsePoint, cached reads); the instance shape is not premature.
    public uint? ReadTag(string fullPath)
    {
        SafeFileHandle handle;
        try
        {
            handle = InventoryNative.OpenForIdentity(fullPath);
        }
        catch (WindowsSecurityException)
        {
            return null;
        }

        using (handle)
        {
            nint buffer = Marshal.AllocHGlobal(8);
            try
            {
                if (!InventoryNative.GetFileInformationByHandleEx(handle,
                    InventoryNative.FileAttributeTagInfoClass, buffer, 8))
                {
                    return null;
                }

                return (uint)Marshal.ReadInt32(buffer + 4);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
