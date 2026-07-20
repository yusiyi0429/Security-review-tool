namespace SecurityReview.Domain.Scans;

public static class ScanStateMachine
{
    private static readonly Dictionary<ScanStatus, HashSet<ScanStatus>> Allowed =
        new()
        {
            [ScanStatus.Draft] = new HashSet<ScanStatus> { ScanStatus.Preflight },
            [ScanStatus.Preflight] = new HashSet<ScanStatus> { ScanStatus.Running, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Running] = new HashSet<ScanStatus> { ScanStatus.Cancelling, ScanStatus.Completed, ScanStatus.Partial, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Cancelling] = new HashSet<ScanStatus> { ScanStatus.Cancelled, ScanStatus.Failed, ScanStatus.Interrupted },
            [ScanStatus.Completed] = new HashSet<ScanStatus>(),
            [ScanStatus.Partial] = new HashSet<ScanStatus>(),
            [ScanStatus.Cancelled] = new HashSet<ScanStatus>(),
            [ScanStatus.Failed] = new HashSet<ScanStatus>(),
            [ScanStatus.Interrupted] = new HashSet<ScanStatus>()
        };

    public static bool CanTransition(ScanStatus current, ScanStatus next) => Allowed[current].Contains(next);

    public static ScanStatus RecoverAfterProcessExit(ScanStatus current) => current switch
    {
        ScanStatus.Preflight or ScanStatus.Running or ScanStatus.Cancelling => ScanStatus.Interrupted,
        _ => current
    };
}
