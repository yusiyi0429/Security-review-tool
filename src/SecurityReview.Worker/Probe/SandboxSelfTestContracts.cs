using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace SecurityReview.Worker.Probe;

// The production worker exposes only these bounded runtime self-test
// scenarios. Fault-injection probe scenarios remain gated behind
// SECURITY_REVIEW_SANDBOX_PROBE.
internal enum SandboxSelfTestScenario
{
    HandleAndSiblingRead,
    NetworkMatrix,
    TokenInspection,
}

[JsonConverter(typeof(JsonStringEnumConverter<ProbeAccess>))]
internal enum ProbeAccess { Unknown, Allowed, Denied, Error }

internal sealed record ProbeNetworkAttempt(
    string Target,
    ProbeAccess Access,
    string? ErrorKind);

internal sealed record SandboxProbeResult(
    string Scenario,
    string? HandleText,
    ProbeAccess SiblingRead,
    ProbeAccess HandleWrite,
    IReadOnlyList<ProbeNetworkAttempt> NetworkAttempts,
    bool IsAppContainer,
    string? AppContainerSid,
    IReadOnlyList<string> TokenCapabilities,
    ProbeAccess ChildSpawn,
    int AllocatedMebiBytes,
    bool GroupEnumerationProven,
    string? Note)
{
    public static SandboxProbeResult Empty(string scenario) => new(
        scenario, null, ProbeAccess.Unknown, ProbeAccess.Unknown,
        [], false, null, [], ProbeAccess.Unknown, 0, false, null);
}

internal sealed class ProbeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private const uint TokenQuery = 0x0008;
    private const uint TokenGroups = 2;
    private const uint TokenIsAppContainer = 29;
    private const uint TokenCapabilities = 30;
    private const uint TokenAppContainerSid = 31;

#pragma warning disable CA1419 // Token handles originate only from OpenCurrent().
    private ProbeTokenHandle()
        : base(true)
    {
    }
#pragma warning restore CA1419

    public static ProbeTokenHandle OpenCurrent()
    {
        if (!ProbeNative.OpenProcessToken(ProbeNative.GetCurrentProcess(), TokenQuery,
            out nint token))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        var handle = new ProbeTokenHandle();
        handle.SetHandle(token);
        return handle;
    }

    public bool IsAppContainer()
    {
        nint buffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!ProbeNative.GetTokenInformation(this, TokenIsAppContainer, buffer,
                sizeof(uint), out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            return Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public string? AppContainerSid()
    {
        uint required = 0;
        if (!ProbeNative.GetTokenInformation(this, TokenAppContainerSid, nint.Zero, 0,
            out required) && Marshal.GetLastPInvokeError() != 122)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        nint buffer = Marshal.AllocHGlobal((int)Math.Max(required, (uint)nint.Size));
        try
        {
            if (!ProbeNative.GetTokenInformation(this, TokenAppContainerSid, buffer,
                required, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            nint sid = Marshal.ReadIntPtr(buffer);
            return sid == nint.Zero ? null : SidToString(sid);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public IReadOnlyList<string> CapabilitySids() => EnumerateSids(TokenCapabilities);

    public IReadOnlyList<string> GroupSids() => EnumerateSids(TokenGroups);

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public nint Sid;
        public uint Attributes;
    }

    private List<string> EnumerateSids(uint informationClass)
    {
        var sids = new List<string>();
        if (!ProbeNative.GetTokenInformation(this, informationClass, nint.Zero, 0,
            out uint required) && Marshal.GetLastPInvokeError() != 122)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        if (required == 0)
            return sids;

        nint buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!ProbeNative.GetTokenInformation(this, informationClass, buffer, required,
                out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            uint count = (uint)Marshal.ReadInt32(buffer);
            int stride = Marshal.SizeOf<SidAndAttributes>();
            nint entry = buffer + nint.Size;
            for (uint i = 0; i < count; i++, entry += stride)
            {
                var sidAndAttributes = Marshal.PtrToStructure<SidAndAttributes>(entry);
                if (sidAndAttributes.Sid != nint.Zero)
                    sids.Add(SidToString(sidAndAttributes.Sid));
            }

            return sids;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    protected override bool ReleaseHandle() => ProbeNative.CloseHandle(handle);

    private static string SidToString(nint sid)
    {
        if (!ProbeNative.ConvertSidToStringSid(sid, out nint native))
            throw new Win32Exception(Marshal.GetLastPInvokeError());

        try
        {
            return Marshal.PtrToStringUni(native) ?? string.Empty;
        }
        finally
        {
            ProbeNative.LocalFree(native);
        }
    }
}

internal static partial class ProbeNative
{
    [LibraryImport("kernel32.dll")]
    internal static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll")]
    internal static partial nint LocalFree(nint hMem);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(nint process, uint desiredAccess,
        out nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(SafeHandle token, uint informationClass,
        nint information, uint informationLength, out uint returnLength);

    [LibraryImport("advapi32.dll", SetLastError = true, EntryPoint = "ConvertSidToStringSidW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ConvertSidToStringSid(nint sid, out nint stringSid);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SandboxProbeResult))]
internal sealed partial class ProbeJsonContext : JsonSerializerContext
{
}
