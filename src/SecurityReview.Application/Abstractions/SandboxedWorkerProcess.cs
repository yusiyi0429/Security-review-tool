using System.Runtime.InteropServices;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Application.Abstractions;

public sealed class SandboxedWorkerProcess : IDisposable
{
    private readonly Action _terminateWorker;
    private bool _disposed;

    public SandboxedWorkerProcess(Stream pipe, ProtocolSessionValidator session,
        SafeHandle processHandle, SafeHandle workerJobHandle, int processId,
        string appContainerSid, string pipeName, long inputHandleValue,
        Action terminateWorker)
    {
        Pipe = pipe;
        Session = session;
        ProcessHandle = processHandle;
        WorkerJobHandle = workerJobHandle;
        ProcessId = processId;
        AppContainerSid = appContainerSid;
        PipeName = pipeName;
        InputHandleValue = inputHandleValue;
        _terminateWorker = terminateWorker;
    }

    public Stream Pipe { get; }
    public ProtocolSessionValidator Session { get; }

    // Owned by this instance; disposed with it. Callers must not dispose it.
    public SafeHandle ProcessHandle { get; }

    // Borrowed; owned by the caller's job set and never disposed here.
    public SafeHandle WorkerJobHandle { get; }
    public int ProcessId { get; }
    public string AppContainerSid { get; }
    public string PipeName { get; }
    public long InputHandleValue { get; }

    public void TerminateWorker() => _terminateWorker();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            _terminateWorker();
        }
        catch (ObjectDisposedException)
        {
            // The owning job set may already be disposed; kill-on-close applies.
        }

        Pipe.Dispose();
        ProcessHandle.Dispose();
    }
}
