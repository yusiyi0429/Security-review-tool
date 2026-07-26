using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Worker.Probe;

// Production-safe runtime checks used by WindowsSandboxSelfTest. Only the
// three allowlisted scenarios below are reachable through --self-test.
internal static class SandboxSelfTestRunner
{
    public static async Task<int> RunAsync(
        string scenarioName,
        WorkerSessionContext context)
    {
        if (!Enum.TryParse(scenarioName, ignoreCase: false,
                out SandboxSelfTestScenario scenario))
        {
            return 2;
        }

        ProtocolEnvelope parseJobMessage = await context.ReadAsync().ConfigureAwait(false);
        if (parseJobMessage.MessageType != MessageType.ParseJob)
            return 4;

        ParseJob? parseJob = JsonSerializer.Deserialize(parseJobMessage.PayloadJson,
            ProtocolJsonContext.Default.ParseJob);
        if (parseJob is null)
            return 4;

        return await RunScenarioAsync(scenario, scenarioName, context, parseJob)
            .ConfigureAwait(false);
    }

    internal static Task<int> RunScenarioAsync(
        SandboxSelfTestScenario scenario,
        string scenarioName,
        WorkerSessionContext context,
        ParseJob parseJob) =>
        scenario switch
        {
            SandboxSelfTestScenario.HandleAndSiblingRead =>
                RunHandleAndSiblingReadAsync(context, parseJob, scenarioName),
            SandboxSelfTestScenario.NetworkMatrix =>
                RunNetworkMatrixAsync(context, parseJob, scenarioName),
            SandboxSelfTestScenario.TokenInspection =>
                RunTokenInspectionAsync(context, scenarioName),
            _ => Task.FromResult(2),
        };

    private static async Task<int> RunHandleAndSiblingReadAsync(
        WorkerSessionContext context,
        ParseJob parseJob,
        string scenarioName)
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

    private static async Task<int> RunNetworkMatrixAsync(
        WorkerSessionContext context,
        ParseJob parseJob,
        string scenarioName)
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

    private static async Task<int> RunTokenInspectionAsync(
        WorkerSessionContext context,
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

    internal static async Task<string?> TryReadHandleTextAsync(long handleValue)
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
                case "tcp" when parts.Length == 3 &&
                    int.TryParse(parts[2], out int tcpPort):
                {
                    using var timeout =
                        new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    using var client = new TcpClient();
                    await client.ConnectAsync(parts[1], tcpPort, timeout.Token)
                        .ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                case "udp" when parts.Length == 3 &&
                    int.TryParse(parts[2], out int udpPort):
                {
                    using var timeout =
                        new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    using var client = new UdpClient();
                    client.Connect(parts[1], udpPort);
                    await client.SendAsync(new byte[] { 0x00 }, 1)
                        .ConfigureAwait(false);
                    await client.SendAsync(new byte[] { 0x00 }, 1)
                        .ConfigureAwait(false);
                    await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                case "dns" when parts.Length == 2:
                {
                    using var timeout =
                        new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    _ = await Dns.GetHostAddressesAsync(parts[1], timeout.Token)
                        .ConfigureAwait(false);
                    return new ProbeNetworkAttempt(target, ProbeAccess.Allowed, null);
                }

                default:
                    return new ProbeNetworkAttempt(
                        target, ProbeAccess.Error, "bad_target");
            }
        }
        catch (Exception ex) when (ex is SocketException or UnauthorizedAccessException
            or IOException)
        {
            return new ProbeNetworkAttempt(
                target, ProbeAccess.Denied, ex.GetType().Name);
        }
        catch (OperationCanceledException)
        {
            return new ProbeNetworkAttempt(
                target, ProbeAccess.Denied, "timeout_blocked");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
            or ObjectDisposedException or NotSupportedException)
        {
            return new ProbeNetworkAttempt(
                target, ProbeAccess.Error, ex.GetType().Name);
        }
    }

    private static string Serialize(SandboxProbeResult result) =>
        JsonSerializer.Serialize(result, ProbeJsonContext.Default.SandboxProbeResult);
}
