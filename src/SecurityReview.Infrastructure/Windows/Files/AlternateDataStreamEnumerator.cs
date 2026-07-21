using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Infrastructure.Windows.Files;

// Enumerates named alternate data streams of one file via
// FindFirstStreamW/FindNextStreamW. The unnamed default ::$DATA entry is
// excluded (it is the file's own default stream, already recorded); non-$DATA
// stream types are excluded as well.
public sealed class AlternateDataStreamEnumerator
{
    private const string DataStreamSuffix = ":$DATA";

#pragma warning disable CA1822 // Helper is intentionally a class for future extension (alternate ADSI providers, cached enumeration); the instance shape is not premature.
    public IReadOnlyList<(string Name, long Size)> Enumerate(string fullPath)
    {
        var streams = new List<(string, long)>();
        nint buffer = Marshal.AllocHGlobal(600);
        SafeFindStreamHandle? find = null;
        try
        {
            find = InventoryStreamNative.FindFirstStream(
                InventoryNative.ToExtendedPath(fullPath), 0, buffer, 0);
            if (find.IsInvalid)
            {
                int error = Marshal.GetLastPInvokeError();
                if (error is 1 /* ERROR_INVALID_FUNCTION: non-NTFS */ or 2 or 3)
                {
                    return streams;
                }

                throw new WindowsSecurityException("FindFirstStreamW", error);
            }

            while (true)
            {
                long size = Marshal.ReadInt64(buffer);
                string raw = Marshal.PtrToStringUni(buffer + 8)
                    ?? string.Empty;
                if (TryParseNamedDataStream(raw, out string? name))
                {
                    streams.Add((name, size));
                }

                if (!InventoryStreamNative.FindNextStream(find, buffer))
                {
                    int error = Marshal.GetLastPInvokeError();
                    if (error != 38 /* ERROR_HANDLE_EOF */)
                    {
                        throw new WindowsSecurityException("FindNextStreamW", error);
                    }

                    break;
                }
            }

            return streams;
        }
        finally
        {
            find?.Dispose();
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryParseNamedDataStream(string raw, out string name)
    {
        name = string.Empty;
        if (raw.Length == 0 || raw[0] != ':'
            || !raw.EndsWith(DataStreamSuffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string candidate = raw[1..^DataStreamSuffix.Length];
        if (candidate.Length == 0)
        {
            return false;
        }

        name = candidate;
        return true;
    }
}

internal sealed class SafeFindStreamHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeFindStreamHandle()
        : base(true)
    {
    }

    protected override bool ReleaseHandle() => InventoryStreamNative.FindClose(handle);
}

internal static partial class InventoryStreamNative
{
    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "FindFirstStreamW",
        StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFindStreamHandle FindFirstStream(string fileName,
        int infoLevel, nint findStreamData, int flags);

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "FindNextStreamW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FindNextStream(SafeFindStreamHandle findStream,
        nint findStreamData);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FindClose(nint findFile);
}
