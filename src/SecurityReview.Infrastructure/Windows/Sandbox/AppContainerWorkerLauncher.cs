using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Application.Abstractions;
using SecurityReview.Infrastructure.Windows.Native;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

// Launches a parser worker inside an AppContainer with zero capabilities,
// nested Job limits, a read-only duplicated input handle, and a restricted
// named pipe. Fail-closed: any error terminates the job and disposes every
// handle; there is no unsandboxed fallback.
public sealed class AppContainerWorkerLauncher : IWorkerLauncher
{
    private const string ManifestFileName = "worker-manifest.json";

    private readonly SandboxLaunchOptions _options;
    private readonly IFileHandleBroker _handleBroker;
    private PreparedWorker? _prepared;

    public AppContainerWorkerLauncher(SandboxLaunchOptions? options = null,
        IFileHandleBroker? handleBroker = null)
    {
        _options = options ?? new SandboxLaunchOptions();
        _handleBroker = handleBroker ?? new WindowsFileHandleBroker();
    }

    // Verifies the staged worker manifest (SHA-256) and only then grants the
    // AppContainer profile access to the staging directory.
    public async Task<AppContainerProfileInfo> PrepareAsync(string workerStagingDirectory,
        string workerExecutableName, CancellationToken cancellationToken)
    {
        PreparedWorker prepared = await EnsurePreparedAsync(workerStagingDirectory,
            workerExecutableName, cancellationToken).ConfigureAwait(false);
        return prepared.Profile;
    }

    public async Task<SandboxedWorkerProcess> LaunchAsync(WorkerLaunchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        PreparedWorker prepared = await EnsurePreparedAsync(request.WorkerStagingDirectory,
            request.WorkerExecutableName, cancellationToken).ConfigureAwait(false);

        NamedPipeServerStream? pipe = null;
        SafeKernelHandle? processHandle = null;
        SafeKernelHandle? threadHandle = null;
        try
        {
            pipe = RestrictedPipeFactory.CreateServerPipe(prepared.Profile.SidString,
                out string pipeName, out _);
            byte[] nonce = RandomNumberGenerator.GetBytes(ProtocolSessionValidator.NonceLength);
            var session = new ProtocolSessionValidator(request.ScanId, request.JobId, nonce,
                prepared.WorkerBuildSha256);
            string commandLine = BuildCommandLine(request, pipeName, nonce);

            (processHandle, threadHandle, int processId) = await CreateWithProfileRetryAsync(
                request, prepared, commandLine, cancellationToken).ConfigureAwait(false);
            // Nested assignment: scan-wide job first, then the per-worker child
            // job nested beneath it. Failure here is fail-closed M0 evidence.
            AssignToJob(request.ScanJobHandle, processHandle);
            AssignToJob(request.WorkerJobHandle, processHandle);

            long inputHandleValue;
            using (var input = new FileStream(request.InputFilePath, FileMode.Open,
                FileAccess.Read, FileShare.Read))
            {
                inputHandleValue = await _handleBroker.DuplicateReadOnlyAsync(
                    input.SafeFileHandle, processHandle, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (NativeMethods.ResumeThread(threadHandle) == -1)
            {
                throw new WindowsSecurityException("ResumeThread",
                    Marshal.GetLastPInvokeError());
            }

            VerifyWorkerTokenSid(processHandle, prepared.Profile.SidString);

            using var handshakeTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            handshakeTimeout.CancelAfter(_options.HandshakeTimeoutMilliseconds);
            await pipe.WaitForConnectionAsync(handshakeTimeout.Token).ConfigureAwait(false);
            (ProtocolEnvelope hello, byte[] rawHello) = await LengthPrefixedJsonProtocol
                .ReadWithRawAsync(pipe, handshakeTimeout.Token).ConfigureAwait(false);
            if (session.Validate(hello, rawHello) != SessionVerdict.Accept)
            {
                throw new ProtocolException("Worker handshake rejected.");
            }

            SafeKernelHandle ownedProcess = processHandle;
            processHandle = null;
            threadHandle.Dispose();
            threadHandle = null;
            NamedPipeServerStream ownedPipe = pipe;
            pipe = null;
            return new SandboxedWorkerProcess(ownedPipe, session, ownedProcess,
                request.WorkerJobHandle, processId, prepared.Profile.SidString, pipeName,
                inputHandleValue, () => TerminateJobQuietly(request.WorkerJobHandle));
        }
        catch
        {
            TerminateJobQuietly(request.WorkerJobHandle);
            // Job termination cannot reap a process whose assignment failed;
            // fail-closed means no suspended or running worker is left behind.
            if (processHandle is not null)
            {
                try
                {
                    NativeMethods.TerminateProcess(processHandle, 1);
                }
                catch (ObjectDisposedException)
                {
                    // Already disposed; nothing left to terminate.
                }
            }

            pipe?.Dispose();
            threadHandle?.Dispose();
            processHandle?.Dispose();
            throw;
        }
    }

    private static void AssignToJob(SafeHandle jobHandle, SafeHandle processHandle)
    {
        if (!NativeMethods.AssignProcessToJobObject(jobHandle, processHandle))
        {
            throw new WindowsSecurityException("AssignProcessToJobObject",
                Marshal.GetLastPInvokeError());
        }
    }

    private static void TerminateJobQuietly(SafeHandle jobHandle)
    {
        try
        {
            if (!jobHandle.IsClosed && !jobHandle.IsInvalid)
            {
                NativeMethods.TerminateJobObject(jobHandle, 1);
            }
        }
        catch (ObjectDisposedException)
        {
            // The job set may already be disposed; kill-on-close applies.
        }
    }

    private static string BuildCommandLine(WorkerLaunchRequest request, string pipeName, byte[] nonce)
    {
        string exePath = Path.Combine(request.WorkerStagingDirectory,
            request.WorkerExecutableName);
        string args = $"\"{exePath}\" --pipe {pipeName} --nonce {Convert.ToBase64String(nonce)}"
            + $" --scan {request.ScanId.Value:N} --job {request.JobId.Value:N}";
        if (!string.IsNullOrWhiteSpace(request.AdditionalWorkerArguments))
        {
            args += " " + request.AdditionalWorkerArguments;
        }

        return args;
    }

    private SafeAppContainerSidHandle DeriveProfileSid()
    {
        int hr = NativeMethods.DeriveAppContainerSidFromAppContainerName(_options.ProfileName,
            out nint sid);
        if (hr != 0)
        {
            throw new WindowsSecurityException("DeriveAppContainerSidFromAppContainerName", hr);
        }

        return new SafeAppContainerSidHandle(sid);
    }

    private async Task<(SafeKernelHandle Process, SafeKernelHandle Thread, int ProcessId)>
        CreateWithProfileRetryAsync(WorkerLaunchRequest request, PreparedWorker prepared,
            string commandLine, CancellationToken cancellationToken)
    {
        try
        {
            using SafeAppContainerSidHandle appContainerSid = DeriveProfileSid();
            return CreateSuspendedAppContainerProcess(prepared.ExecutablePath, commandLine,
                request.WorkerStagingDirectory, appContainerSid);
        }
        catch (WindowsSecurityException ex) when (ex.ApiName == "CreateProcessW"
            && ex.ErrorCode == 2 /* ERROR_FILE_NOT_FOUND: profile reclaimed by the OS */)
        {
            // Force profile re-creation and retry the create exactly once; a
            // second failure stays fail-closed.
            var profile = new AppContainerProfile(_options.ProfileName);
            profile.Invalidate(request.WorkerStagingDirectory);
            await profile.EnsureAsync(request.WorkerStagingDirectory, cancellationToken)
                .ConfigureAwait(false);
        }

        using SafeAppContainerSidHandle retrySid = DeriveProfileSid();
        return CreateSuspendedAppContainerProcess(prepared.ExecutablePath, commandLine,
            request.WorkerStagingDirectory, retrySid);
    }

    private static (SafeKernelHandle Process, SafeKernelHandle Thread, int ProcessId)
        CreateSuspendedAppContainerProcess(string executablePath, string commandLine,
            string workingDirectory, SafeHandle appContainerSid)
    {
        nuint attributeSize = 0;
        NativeMethods.InitializeProcThreadAttributeList(nint.Zero, 1, 0, ref attributeSize);
        nint attributeList = Marshal.AllocHGlobal((nint)attributeSize);
        try
        {
            if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 1, 0,
                ref attributeSize))
            {
                throw new WindowsSecurityException("InitializeProcThreadAttributeList",
                    Marshal.GetLastPInvokeError());
            }

            try
            {
                var capabilities = new NativeMethods.SecurityCapabilities
                {
                    AppContainerSid = appContainerSid.DangerousGetHandle(),
                    Capabilities = nint.Zero,
                    CapabilityCount = 0,
                    Reserved = 0,
                };
                if (!NativeMethods.UpdateProcThreadAttribute(attributeList, 0,
                    NativeMethods.ProcThreadAttributeSecurityCapabilities, ref capabilities,
                    (nuint)Marshal.SizeOf<NativeMethods.SecurityCapabilities>(),
                    nint.Zero, nint.Zero))
                {
                    throw new WindowsSecurityException("UpdateProcThreadAttribute",
                        Marshal.GetLastPInvokeError());
                }

                var startupInfo = new NativeMethods.StartupInfoExW
                {
                    StartupInfo = new NativeMethods.StartupInfoW
                    {
                        // With EXTENDED_STARTUPINFO_PRESENT, cb must cover the
                        // full STARTUPINFOEX (sizeof(STARTUPINFO) is rejected
                        // with ERROR_INVALID_PARAMETER on current builds).
                        cb = (uint)Marshal.SizeOf<NativeMethods.StartupInfoExW>(),
                    },
                    AttributeList = attributeList,
                };
                char[] commandLineBuffer = (commandLine + '\0').ToCharArray();
                uint flags = NativeMethods.CreateSuspended
                    | NativeMethods.ExtendedStartupInfoPresent
                    | NativeMethods.CreateNoWindow
                    | NativeMethods.CreateUnicodeEnvironment;
                if (!NativeMethods.CreateProcess(executablePath, commandLineBuffer,
                    nint.Zero, nint.Zero, false, flags, nint.Zero, workingDirectory,
                    ref startupInfo, out NativeMethods.ProcessInformation information))
                {
                    throw new WindowsSecurityException("CreateProcessW",
                        Marshal.GetLastPInvokeError());
                }

                return (new SafeKernelHandle(information.Process, ownsHandle: true),
                    new SafeKernelHandle(information.Thread, ownsHandle: true),
                    (int)information.ProcessId);
            }
            finally
            {
                NativeMethods.DeleteProcThreadAttributeList(attributeList);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(attributeList);
        }
    }

    private static void VerifyWorkerTokenSid(SafeHandle processHandle, string expectedSid)
    {
        if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TokenQuery,
            out nint rawToken))
        {
            throw new WindowsSecurityException("OpenProcessToken",
                Marshal.GetLastPInvokeError());
        }

        using var token = new SafeKernelHandle(rawToken, ownsHandle: true);
        uint required = 0;
        if (!NativeMethods.GetTokenInformation(token, NativeMethods.TokenAppContainerSid,
            nint.Zero, 0, out required)
            && Marshal.GetLastPInvokeError() != 122 /* ERROR_INSUFFICIENT_BUFFER */)
        {
            throw new WindowsSecurityException("GetTokenInformation",
                Marshal.GetLastPInvokeError());
        }

        if (required < (uint)nint.Size)
        {
            throw new WindowsSecurityException("GetTokenInformation", 0);
        }

        nint buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!NativeMethods.GetTokenInformation(token, NativeMethods.TokenAppContainerSid,
                buffer, required, out _))
            {
                throw new WindowsSecurityException("GetTokenInformation",
                    Marshal.GetLastPInvokeError());
            }

            nint tokenSid = Marshal.ReadIntPtr(buffer);
            if (tokenSid == nint.Zero)
            {
                throw new WindowsSecurityException("GetTokenInformation", 0);
            }

            using var sidHandle = new SafeKernelHandle(tokenSid, ownsHandle: false);
            string actualSid = AppContainerProfile.SidToString(sidHandle);
            if (!string.Equals(actualSid, expectedSid, StringComparison.OrdinalIgnoreCase))
            {
                throw new WindowsSecurityException("VerifyWorkerTokenSid", 0xC000_0028);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private async Task<PreparedWorker> EnsurePreparedAsync(string stagingDirectory,
        string executableName, CancellationToken cancellationToken)
    {
        if (_prepared is not null
            && string.Equals(_prepared.StagingDirectory, stagingDirectory,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals(_prepared.ExecutableName, executableName,
                StringComparison.OrdinalIgnoreCase))
        {
            return _prepared;
        }

        string workerHash = await WorkerManifestVerifier
            .VerifyAndGetWorkerHashAsync(stagingDirectory, executableName, cancellationToken)
            .ConfigureAwait(false);
        var profile = new AppContainerProfile(_options.ProfileName);
        AppContainerProfileInfo info = await profile
            .EnsureAsync(stagingDirectory, cancellationToken).ConfigureAwait(false);
        _prepared = new PreparedWorker(stagingDirectory, executableName,
            Path.Combine(stagingDirectory, executableName), workerHash, info);
        return _prepared;
    }

    private sealed record PreparedWorker(string StagingDirectory, string ExecutableName,
        string ExecutablePath, string WorkerBuildSha256, AppContainerProfileInfo Profile);

    // Verifies every staged file against the SHA-256 manifest produced by the
    // trusted publish step. Any mismatch or missing entry fails closed.
    private static class WorkerManifestVerifier
    {
        public static async Task<string> VerifyAndGetWorkerHashAsync(string stagingDirectory,
            string executableName, CancellationToken cancellationToken)
        {
            string manifestPath = Path.Combine(stagingDirectory, ManifestFileName);
            if (!File.Exists(manifestPath))
            {
                throw new WindowsSecurityException("VerifyWorkerManifest", 2);
            }

            Dictionary<string, string> files;
            await using (FileStream stream = new(manifestPath, FileMode.Open,
                FileAccess.Read, FileShare.Read))
            {
                files = ParseManifest(await JsonDocument.ParseAsync(stream,
                    cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            if (!files.TryGetValue(executableName, out string? workerHash))
            {
                throw new WindowsSecurityException("VerifyWorkerManifest", 0x8007_0002);
            }

            foreach ((string name, string expectedHex) in files)
            {
                if (name.IndexOfAny(['/', '\\']) >= 0 || name == ManifestFileName)
                {
                    throw new WindowsSecurityException("VerifyWorkerManifest", 0x8007_0057);
                }

                string path = Path.Combine(stagingDirectory, name);
                if (!File.Exists(path))
                {
                    throw new WindowsSecurityException("VerifyWorkerManifest", 2);
                }

                byte[] expected;
                try
                {
                    expected = Convert.FromHexString(expectedHex);
                }
                catch (FormatException)
                {
                    throw new WindowsSecurityException("VerifyWorkerManifest", 0x8007_0057);
                }

                byte[] actual;
                await using (FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                    FileShare.Read))
                {
                    actual = await SHA256.HashDataAsync(stream, cancellationToken)
                        .ConfigureAwait(false);
                }
                if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                {
                    throw new WindowsSecurityException("VerifyWorkerManifest", 0x8007_06F0);
                }
            }

            return workerHash.ToLowerInvariant();
        }

        private static Dictionary<string, string> ParseManifest(JsonDocument document)
        {
            using (document)
            {
                JsonElement root = document.RootElement;
                if (!root.TryGetProperty("algorithm", out JsonElement algorithm)
                    || !string.Equals(algorithm.GetString(), "SHA256",
                        StringComparison.OrdinalIgnoreCase)
                    || !root.TryGetProperty("files", out JsonElement filesElement)
                    || filesElement.ValueKind != JsonValueKind.Object)
                {
                    throw new WindowsSecurityException("VerifyWorkerManifest", 0x8007_0057);
                }

                var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty entry in filesElement.EnumerateObject())
                {
                    if (entry.Value.ValueKind != JsonValueKind.String)
                    {
                        throw new WindowsSecurityException("VerifyWorkerManifest",
                            0x8007_0057);
                    }

                    files[entry.Name] = entry.Value.GetString()!;
                }

                return files;
            }
        }
    }
}
