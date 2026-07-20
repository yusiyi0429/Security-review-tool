#if SECURITY_REVIEW_SANDBOX_PROBE
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Worker.Probe;

// Executes the bounded, probe-only scenarios. Compiled only into the
// SECURITY_REVIEW_SANDBOX_PROBE build; results contain fixed canary labels
// and access classifications, never file content or raw exception messages.
internal static class ProbeRunner
{
    public const uint MemoryLimitExitCode = 86;

    public static (byte[] Nonce, string Build) ApplyHandshakeSpoof(
        string? scenarioName, byte[] nonce, string build)
    {
        if (scenarioName == nameof(ProbeScenario.ProtocolWrongNonce) && nonce.Length > 0)
        {
            byte[] spoofed = [.. nonce];
            spoofed[0] ^= 0xFF;
            return (spoofed, build);
        }

        if (scenarioName == nameof(ProbeScenario.ProtocolWrongBuild))
        {
            return (nonce, new string('0', 64));
        }

        return (nonce, build);
    }

    public static async Task<int> RunAsync(string scenarioName, WorkerSessionContext context)
    {
        if (!Enum.TryParse(scenarioName, ignoreCase: false, out ProbeScenario scenario))
        {
            return 2;
        }

        switch (scenario)
        {
            case ProbeScenario.ProtocolSkipSequence:
                await context.SendAsync(MessageType.ContentChunk, "{}", sequenceOverride: 5)
                    .ConfigureAwait(false);
                return 0;
            case ProbeScenario.ProtocolConflictingDuplicate:
                await context.SendAsync(MessageType.ContentChunk, "{\"marker\":\"a\"}",
                    sequenceOverride: 1).ConfigureAwait(false);
                await context.SendAsync(MessageType.ContentChunk, "{\"marker\":\"b\"}",
                    sequenceOverride: 1).ConfigureAwait(false);
                return 0;
            case ProbeScenario.ProtocolExactRetransmit:
            {
                byte[] chunk = context.SerializeFrame(MessageType.ContentChunk, "{}", 1);
                await context.WriteRawFrameAsync(chunk).ConfigureAwait(false);
                await context.WriteRawFrameAsync(chunk).ConfigureAwait(false);
                SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
                {
                    Note = "retransmission_sent",
                };
                await context.SendAsync(MessageType.ParseCompleted, Serialize(result),
                    sequenceOverride: 2).ConfigureAwait(false);
                return 0;
            }

            case ProbeScenario.ProtocolOversizedFrame:
            {
                byte[] header = new byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
                    header, ProtocolConstants.MaxFrameBytes + 1);
                await context.Pipe.WriteAsync(header).ConfigureAwait(false);
                await context.Pipe.WriteAsync(new byte[64]).ConfigureAwait(false);
                await context.Pipe.FlushAsync().ConfigureAwait(false);
                return 0;
            }

            case ProbeScenario.ProtocolWrongNonce:
            case ProbeScenario.ProtocolWrongBuild:
                // The spoof already happened in the Hello handshake; the parent
                // must have rejected it, so reaching this point is a failure.
                return 5;
            default:
                break;
        }

        if (scenario == ProbeScenario.HangPastDeadline)
        {
            await Task.Delay(Timeout.Infinite).ConfigureAwait(false);
            return 0;
        }

        if (scenario == ProbeScenario.CrashNonZero)
        {
            return 3;
        }

        ProtocolEnvelope parseJobMessage = await context.ReadAsync().ConfigureAwait(false);
        if (parseJobMessage.MessageType != MessageType.ParseJob)
        {
            return 4;
        }

        ParseJob? parseJob = JsonSerializer.Deserialize(parseJobMessage.PayloadJson,
            ProtocolJsonContext.Default.ParseJob);
        if (parseJob is null)
        {
            return 4;
        }

        switch (scenario)
        {
            case ProbeScenario.HandleAndSiblingRead:
                return await RunHandleAndSiblingReadAsync(context, parseJob, scenarioName)
                    .ConfigureAwait(false);
            case ProbeScenario.NetworkMatrix:
                return await RunNetworkMatrixAsync(context, parseJob, scenarioName)
                    .ConfigureAwait(false);
            case ProbeScenario.TokenInspection:
                return await RunTokenInspectionAsync(context, scenarioName)
                    .ConfigureAwait(false);
            case ProbeScenario.SpawnChild:
                return await RunSpawnChildAsync(context, scenarioName).ConfigureAwait(false);
            case ProbeScenario.Allocate512MiB:
                return await RunAllocateAsync(context, scenarioName).ConfigureAwait(false);
            case ProbeScenario.HandleReuseAfterDispose:
                return await RunHandleReuseAsync(context, parseJob, scenarioName)
                    .ConfigureAwait(false);
            default:
                return 2;
        }
    }

    private static async Task<int> RunHandleAndSiblingReadAsync(
        WorkerSessionContext context, ParseJob parseJob, string scenarioName)
    {
        string? handleText = await TryReadHandleTextAsync(parseJob.InputHandle)
            .ConfigureAwait(false);
        ProbeAccess handleWrite = await TryWriteHandleAsync(parseJob.InputHandle)
            .ConfigureAwait(false);
        ProbeAccess siblingRead = Probe(() =>
        {
            using FileStream stream = new(parseJob.DisplayVirtualPath, FileMode.Open,
                FileAccess.Read, FileShare.Read);
            byte[] buffer = new byte[16];
            return stream.Read(buffer);
        });

        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            HandleText = handleText,
            HandleWrite = handleWrite,
            SiblingRead = siblingRead,
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunHandleReuseAsync(WorkerSessionContext context,
        ParseJob parseJob, string scenarioName)
    {
        string? firstRead = await TryReadHandleTextAsync(parseJob.InputHandle)
            .ConfigureAwait(false);
        await context.SendAsync(MessageType.ContentChunk, "{}").ConfigureAwait(false);

        // The parent disposes the job while we wait; the second read must never
        // reach the parent if the kill works.
        await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        string? secondRead = await TryReadHandleTextAsync(parseJob.InputHandle)
            .ConfigureAwait(false);
        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            HandleText = firstRead,
            Note = secondRead is null ? "second_read_failed" : "second_read_ok",
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunNetworkMatrixAsync(WorkerSessionContext context,
        ParseJob parseJob, string scenarioName)
    {
        var attempts = new List<ProbeNetworkAttempt>();
        foreach (string target in parseJob.RequestedExtractors)
        {
            attempts.Add(await AttemptNetworkAsync(target).ConfigureAwait(false));
        }

        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            NetworkAttempts = attempts,
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunTokenInspectionAsync(WorkerSessionContext context,
        string scenarioName)
    {
        bool isAppContainer = false;
        string? appContainerSid = null;
        var capabilities = new List<string>();
        bool groupEnumerationProven = false;
        string? note = null;
        try
        {
            using ProbeTokenHandle token = ProbeTokenHandle.OpenCurrent();
            isAppContainer = token.IsAppContainer();
            appContainerSid = token.AppContainerSid();
            capabilities.AddRange(token.CapabilitySids());
            // Every token contains the Everyone group; locating it through the
            // same enumeration path proves the stride-correct parsing works,
            // so an empty capability list is evidence rather than a parse bug.
            groupEnumerationProven = token.GroupSids()
                .Contains("S-1-1-0", StringComparer.OrdinalIgnoreCase);
        }
        catch (Win32Exception)
        {
            note = "token_inspection_failed";
        }

        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            IsAppContainer = isAppContainer,
            AppContainerSid = appContainerSid,
            TokenCapabilities = capabilities,
            GroupEnumerationProven = groupEnumerationProven,
            Note = note,
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunSpawnChildAsync(WorkerSessionContext context,
        string scenarioName)
    {
        ProbeAccess childSpawn;
        try
        {
            using Process? child = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 7")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            if (child is null)
            {
                childSpawn = ProbeAccess.Denied;
            }
            else if (await Task.Run(() => child.WaitForExit(5_000)).ConfigureAwait(false))
            {
                childSpawn = child.ExitCode == 7 ? ProbeAccess.Allowed : ProbeAccess.Denied;
            }
            else
            {
                child.Kill(entireProcessTree: false);
                childSpawn = ProbeAccess.Error;
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException
            or UnauthorizedAccessException or System.IO.IOException)
        {
            childSpawn = ProbeAccess.Denied;
        }

        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            ChildSpawn = childSpawn,
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunAllocateAsync(WorkerSessionContext context,
        string scenarioName)
    {
        try
        {
            var blocks = new List<byte[]>(64);
            for (int i = 0; i < 64; i++)
            {
                byte[] block = GC.AllocateUninitializedArray<byte>(8 * 1024 * 1024);
                block.AsSpan().Fill(0x5A);
                blocks.Add(block);
            }

            GC.KeepAlive(blocks);
        }
        catch (OutOfMemoryException)
        {
            return (int)MemoryLimitExitCode;
        }

        SandboxProbeResult result = SandboxProbeResult.Empty(scenarioName) with
        {
            AllocatedMebiBytes = 512,
        };
        await context.SendAsync(MessageType.ParseCompleted, Serialize(result))
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<string?> TryReadHandleTextAsync(long handleValue)
    {
        try
        {
            using var handle = new SafeFileHandle((nint)handleValue, ownsHandle: false);
            using var stream = new FileStream(handle, FileAccess.Read);
            using var reader = new StreamReader(stream);
            string text = await reader.ReadToEndAsync().ConfigureAwait(false);
            return text.Trim();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
            or ArgumentException or NotSupportedException or ObjectDisposedException)
        {
            return null;
        }
    }

    private static async Task<ProbeAccess> TryWriteHandleAsync(long handleValue)
    {
        try
        {
            using var handle = new SafeFileHandle((nint)handleValue, ownsHandle: false);
            // Buffer size 1 forces an immediate WriteFile instead of a buffered
            // success that would only fail later on flush.
            using var stream = new FileStream(handle, FileAccess.Write, bufferSize: 1);
            await stream.WriteAsync(new byte[] { 0x00 }).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
            return ProbeAccess.Allowed;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
            or ArgumentException or NotSupportedException or ObjectDisposedException)
        {
            return ProbeAccess.Denied;
        }
    }

    private static ProbeAccess Probe(Func<object?> attempt)
    {
        try
        {
            _ = attempt();
            return ProbeAccess.Allowed;
        }
        catch (UnauthorizedAccessException)
        {
            return ProbeAccess.Denied;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException
            or NotSupportedException)
        {
            return ProbeAccess.Error;
        }
    }

    private static async Task<ProbeNetworkAttempt> AttemptNetworkAsync(string target)
    {
        string[] parts = target.Split(':');
        try
        {
            switch (parts[0])
            {
                case "tcp" when parts.Length == 3 && int.TryParse(parts[2], out int tcpPort):
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    using var client = new TcpClient();
                    await client.ConnectAsync(parts[1], tcpPort, timeout.Token)
                        .ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                case "udp" when parts.Length == 3 && int.TryParse(parts[2], out int udpPort):
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    using var client = new UdpClient();
                    client.Connect(parts[1], udpPort);
                    // A blocked datagram can surface on the next socket operation,
                    // so probe past the first fire-and-forget send.
                    await client.SendAsync(new byte[] { 0x00 }, 1).ConfigureAwait(false);
                    await client.SendAsync(new byte[] { 0x00 }, 1).ConfigureAwait(false);
                    await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                case "dns" when parts.Length == 2:
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    _ = await Dns.GetHostAddressesAsync(parts[1], timeout.Token)
                        .ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                default:
                    return new ProbeNetworkAttempt(target, ProbeAccess.Error, "bad_target");
            }
        }
        catch (Exception ex) when (ex is SocketException or UnauthorizedAccessException
            or IOException)
        {
            return new ProbeNetworkAttempt(target, ProbeAccess.Denied, ex.GetType().Name);
        }
        catch (OperationCanceledException)
        {
            // No connection within the budget although every TCP target has a
            // live listener and DNS would resolve: the sandbox dropped it.
            return new ProbeNetworkAttempt(target, ProbeAccess.Denied, "timeout_blocked");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
            or ObjectDisposedException or NotSupportedException)
        {
            return new ProbeNetworkAttempt(target, ProbeAccess.Error, ex.GetType().Name);
        }
    }

    private static string Serialize(SandboxProbeResult result) =>
        JsonSerializer.Serialize(result, ProbeJsonContext.Default.SandboxProbeResult);
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

    // Both TokenCapabilities and TokenGroups return a TOKEN_GROUPS-shaped
    // buffer: DWORD Count, then an array of SID_AND_ATTRIBUTES
    // { PSID Sid; DWORD Attributes; }. On x64 the pointer alignment inserts
    // 4 bytes of padding after the count and after Attributes, so the first
    // entry starts at offset 8 and the stride is 16; on x86 both are exact
    // (4 and 8). nint.Size and Marshal.SizeOf express this without magic
    // constants.
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
        {
            return sids;
        }

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
                {
                    sids.Add(SidToString(sidAndAttributes.Sid));
                }
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
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

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
#endif
