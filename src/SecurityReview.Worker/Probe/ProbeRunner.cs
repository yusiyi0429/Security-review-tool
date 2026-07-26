#if SECURITY_REVIEW_SANDBOX_PROBE
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
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
                return await SandboxSelfTestRunner.RunScenarioAsync(
                        SandboxSelfTestScenario.HandleAndSiblingRead,
                        scenarioName, context, parseJob)
                    .ConfigureAwait(false);
            case ProbeScenario.NetworkMatrix:
                return await SandboxSelfTestRunner.RunScenarioAsync(
                        SandboxSelfTestScenario.NetworkMatrix,
                        scenarioName, context, parseJob)
                    .ConfigureAwait(false);
            case ProbeScenario.TokenInspection:
                return await SandboxSelfTestRunner.RunScenarioAsync(
                        SandboxSelfTestScenario.TokenInspection,
                        scenarioName, context, parseJob)
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

    private static async Task<int> RunHandleReuseAsync(WorkerSessionContext context,
        ParseJob parseJob, string scenarioName)
    {
        string? firstRead = await SandboxSelfTestRunner
            .TryReadHandleTextAsync(parseJob.InputHandle)
            .ConfigureAwait(false);
        await context.SendAsync(MessageType.ContentChunk, "{}").ConfigureAwait(false);

        // The parent disposes the job while we wait; the second read must never
        // reach the parent if the kill works.
        await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        string? secondRead = await SandboxSelfTestRunner
            .TryReadHandleTextAsync(parseJob.InputHandle)
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

    private static string Serialize(SandboxProbeResult result) =>
        JsonSerializer.Serialize(result, ProbeJsonContext.Default.SandboxProbeResult);
}
#endif
