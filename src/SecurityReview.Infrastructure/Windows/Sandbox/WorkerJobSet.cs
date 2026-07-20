namespace SecurityReview.Infrastructure.Windows.Sandbox;

public sealed record ScanJobLimits(int ActiveProcessLimit, long JobMemoryBytes, bool KillOnJobClose)
{
    public static ScanJobLimits ScanDefault => new(
        ActiveProcessLimit: 4,
        JobMemoryBytes: 1_073_741_824,
        KillOnJobClose: true);
}

public sealed record WorkerJobLimits(int ActiveProcessLimit, long ProcessMemoryBytes,
    bool KillOnJobClose, bool DieOnUnhandledException)
{
    public static WorkerJobLimits OrdinaryWorker => new(
        ActiveProcessLimit: 1,
        ProcessMemoryBytes: 402_653_184,
        KillOnJobClose: true,
        DieOnUnhandledException: true);

    public static WorkerJobLimits OciExclusiveWorker => OrdinaryWorker with
    {
        ProcessMemoryBytes = 1_073_741_824,
    };
}

// Owns the scan-wide Job and every per-worker child Job nested beneath it.
// Disposing the set closes the scan Job, whose kill-on-close flag reaps any
// remaining workers.
public sealed class WorkerJobSet : IDisposable
{
    private readonly List<WorkerJob> _workerJobs = [];
    private bool _disposed;

    private WorkerJobSet(WorkerJob scanJob)
    {
        ScanJob = scanJob;
    }

    public WorkerJob ScanJob { get; }

    public static WorkerJobSet Create(ScanJobLimits limits)
    {
        WorkerJob scanJob = WorkerJob.Create();
        try
        {
            scanJob.ApplyLimits(limits);
            return new WorkerJobSet(scanJob);
        }
        catch
        {
            scanJob.Dispose();
            throw;
        }
    }

    public WorkerJob CreateWorkerJob(WorkerJobLimits limits)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        WorkerJob workerJob = WorkerJob.Create();
        try
        {
            workerJob.ApplyLimits(limits);
            lock (_workerJobs)
            {
                _workerJobs.Add(workerJob);
            }

            return workerJob;
        }
        catch
        {
            workerJob.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        // Closing the scan Job first kills all workers via kill-on-close; the
        // child handles are then released without further side effects.
        ScanJob.Dispose();
        lock (_workerJobs)
        {
            foreach (WorkerJob job in _workerJobs)
            {
                job.Dispose();
            }

            _workerJobs.Clear();
        }
    }
}
