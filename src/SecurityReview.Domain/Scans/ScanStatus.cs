namespace SecurityReview.Domain.Scans;

public enum ScanStatus
{
    Draft, Preflight, Running, Cancelling, Completed, Partial, Cancelled, Failed, Interrupted
}
