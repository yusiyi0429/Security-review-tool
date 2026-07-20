using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class ScanStateMachineTests
{
    [Theory]
    [InlineData(ScanStatus.Draft, ScanStatus.Preflight)]
    [InlineData(ScanStatus.Preflight, ScanStatus.Running)]
    [InlineData(ScanStatus.Preflight, ScanStatus.Failed)]
    [InlineData(ScanStatus.Running, ScanStatus.Cancelling)]
    [InlineData(ScanStatus.Running, ScanStatus.Completed)]
    [InlineData(ScanStatus.Running, ScanStatus.Partial)]
    [InlineData(ScanStatus.Running, ScanStatus.Failed)]
    [InlineData(ScanStatus.Cancelling, ScanStatus.Cancelled)]
    public void Allows_declared_transition(ScanStatus current, ScanStatus next) =>
        Assert.True(ScanStateMachine.CanTransition(current, next));

    [Theory]
    [InlineData(ScanStatus.Draft, ScanStatus.Completed)]
    [InlineData(ScanStatus.Completed, ScanStatus.Running)]
    [InlineData(ScanStatus.Partial, ScanStatus.Completed)]
    [InlineData(ScanStatus.Cancelled, ScanStatus.Running)]
    public void Rejects_undeclared_transition(ScanStatus current, ScanStatus next) =>
        Assert.False(ScanStateMachine.CanTransition(current, next));

    [Theory]
    [InlineData(ScanStatus.Preflight)]
    [InlineData(ScanStatus.Running)]
    [InlineData(ScanStatus.Cancelling)]
    public void Recovery_maps_non_terminal_work_to_interrupted(ScanStatus status) =>
        Assert.Equal(ScanStatus.Interrupted, ScanStateMachine.RecoverAfterProcessExit(status));
}
