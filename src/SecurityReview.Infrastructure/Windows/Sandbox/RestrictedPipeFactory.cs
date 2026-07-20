using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

// Creates single-instance, byte-mode named pipes whose DACL contains exactly
// two ACEs: the current user and the exact AppContainer SID. No Everyone,
// Users, Authenticated Users, or all-AppPackages ACE is ever added.
public sealed class RestrictedPipeFactory
{
    public const int PipeBufferBytes = 1_048_576;

    public static NamedPipeServerStream CreateServerPipe(string appContainerSid,
        out string pipeName, out string appliedSddl)
    {
        ArgumentException.ThrowIfNullOrEmpty(appContainerSid);
        string userSid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new WindowsSecurityException("WindowsIdentity.GetCurrent", 0);
        pipeName = "srt-worker-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
            .ToLowerInvariant();
        appliedSddl = FormattableString.Invariant(
            $"O:{userSid}G:{userSid}D:(A;;GA;;;{userSid})(A;;GA;;;{appContainerSid})");

        if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
            appliedSddl, 1, out nint rawDescriptor, nint.Zero))
        {
            throw new WindowsSecurityException(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                Marshal.GetLastPInvokeError());
        }

        using var descriptor = new SafeSecurityDescriptorHandle(rawDescriptor);
        var attributes = new NativeMethods.SecurityAttributes
        {
            Length = (uint)Marshal.SizeOf<NativeMethods.SecurityAttributes>(),
            SecurityDescriptor = descriptor.DangerousGetHandle(),
            InheritHandle = 0,
        };
        nint rawPipe = NativeMethods.CreateNamedPipe(
            @"\\.\pipe\" + pipeName,
            NativeMethods.PipeAccessDuplex | NativeMethods.FileFlagOverlapped
                | NativeMethods.FileFlagFirstPipeInstance,
            NativeMethods.PipeTypeByte | NativeMethods.PipeReadmodeByte
                | NativeMethods.PipeWait | NativeMethods.PipeRejectRemoteClients,
            1, PipeBufferBytes, PipeBufferBytes, 0, ref attributes);
        if (rawPipe == -1)
        {
            throw new WindowsSecurityException("CreateNamedPipeW",
                Marshal.GetLastPInvokeError());
        }

        var safePipe = new SafePipeHandle(rawPipe, ownsHandle: true);
        try
        {
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true,
                isConnected: false, safePipe);
        }
        catch
        {
            safePipe.Dispose();
            throw;
        }
    }
}
