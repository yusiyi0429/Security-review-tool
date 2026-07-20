using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanRunTests
{
    private static ScanRun NewRun(ScanStatus status = ScanStatus.Draft) =>
        new(new ScanId(Guid.NewGuid()), status,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch,
            "rules-v1", "client-v1", "pipeline-v1", PlannedCount: 10, Version: 0);

    [Fact]
    public void Legal_transition_moves_status_and_timestamp()
    {
        var run = NewRun();
        var atUtc = new DateTimeOffset(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

        var moved = run.TransitionTo(ScanStatus.Preflight, atUtc);

        Assert.Equal(ScanStatus.Preflight, moved.Status);
        Assert.Equal(atUtc, moved.UpdatedAtUtc);
        Assert.Equal(run.ScanId, moved.ScanId);
        Assert.Equal(run.CreatedAtUtc, moved.CreatedAtUtc);
        Assert.Equal(run.Version, moved.Version);
        Assert.Equal(ScanStatus.Draft, run.Status);
    }

    [Fact]
    public void Illegal_transition_throws_invalid_operation()
    {
        var run = NewRun(ScanStatus.Completed);

        Assert.Throws<InvalidOperationException>(() =>
            run.TransitionTo(ScanStatus.Running, DateTimeOffset.UtcNow));
    }
}
