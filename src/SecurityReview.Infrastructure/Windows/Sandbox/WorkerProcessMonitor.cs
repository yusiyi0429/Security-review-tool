using System.Runtime.InteropServices;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

public static class WorkerProcessMonitor
{
    public static bool WaitForExit(SafeHandle processHandle, int milliseconds)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        uint timeout = milliseconds < 0 ? 0xFFFF_FFFF : (uint)milliseconds;
        return NativeMethods.WaitForSingleObject(processHandle, timeout)
            == NativeMethods.WaitObject0;
    }

    public static bool TryGetExitCode(SafeHandle processHandle, out uint exitCode)
    {
        ArgumentNullException.ThrowIfNull(processHandle);
        if (!NativeMethods.GetExitCodeProcess(processHandle, out exitCode))
        {
            return false;
        }

        return exitCode != NativeMethods.StillActive;
    }
}
