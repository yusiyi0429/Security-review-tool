using System.Runtime.InteropServices;
using SecurityReview.Domain;

namespace SecurityReview.Application.Abstractions;

public sealed record WorkerLaunchRequest(
    ScanId ScanId,
    JobId JobId,
    string WorkerStagingDirectory,
    string WorkerExecutableName,
    string InputFilePath,
    SafeHandle ScanJobHandle,
    SafeHandle WorkerJobHandle,
    string? AdditionalWorkerArguments);

public interface IWorkerLauncher
{
    // Launches a sandboxed worker. Fail-closed: any sandbox, integrity, or
    // handshake failure throws and leaves no unsandboxed process behind.
    Task<SandboxedWorkerProcess> LaunchAsync(WorkerLaunchRequest request,
        CancellationToken cancellationToken);
}
