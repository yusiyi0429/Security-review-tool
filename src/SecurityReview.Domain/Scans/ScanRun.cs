namespace SecurityReview.Domain.Scans;

public sealed record ScanRun(
    ScanId ScanId,
    ScanStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string RuleFingerprint,
    string ClientFingerprint,
    string PipelineFingerprint,
    long PlannedCount,
    long Version)
{
    public ScanRun TransitionTo(ScanStatus next, DateTimeOffset atUtc)
    {
        if (!ScanStateMachine.CanTransition(Status, next))
        {
            throw new InvalidOperationException(
                $"Cannot transition scan from {Status} to {next}.");
        }

        return this with { Status = next, UpdatedAtUtc = atUtc };
    }
}
