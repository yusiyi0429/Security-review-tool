using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Terminal failure reason reported by a parser worker. The orchestrator maps
/// each value to a <see cref="GapReason"/> via <see cref="WorkerFailureMapper"/>.
/// </summary>
public enum WorkerFailure
{
    /// <summary>The worker exceeded its absolute deadline.</summary>
    Timeout,

    /// <summary>The worker exceeded its memory budget.</summary>
    MemoryLimit,

    /// <summary>The worker violated the protocol (wrong sequence, bad frame).</summary>
    ProtocolViolation,

    /// <summary>The worker process crashed or exited unexpectedly.</summary>
    Crash,

    /// <summary>The worker was cancelled by the orchestrator.</summary>
    Cancelled,
}

/// <summary>Maps <see cref="WorkerFailure"/> values to <see cref="GapReason"/>.</summary>
public static class WorkerFailureMapper
{
    public static GapReason MapFailure(WorkerFailure failure) => failure switch
    {
        WorkerFailure.Timeout => GapReason.ParserTimeout,
        WorkerFailure.MemoryLimit => GapReason.ParserMemory,
        WorkerFailure.ProtocolViolation => GapReason.ParserProtocolMismatch,
        WorkerFailure.Crash => GapReason.ParserCrash,
        WorkerFailure.Cancelled => GapReason.Cancelled,
        _ => GapReason.Corrupt
    };
}
