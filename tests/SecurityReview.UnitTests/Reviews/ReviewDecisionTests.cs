using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.UnitTests.Reviews;

public sealed class ReviewDecisionTests
{
    private static ScanId SampleScanId => new(Guid.NewGuid());
    private static FindingOccurrenceId SampleOccurrenceId => new(Guid.NewGuid());

    [Fact]
    public void Create_pending_decision_succeeds_without_reason()
    {
        var decision = ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.Pending, "manual_review", null,
            "user-sid-hmac-abc", DateTimeOffset.UtcNow);

        Assert.Equal(ReviewStatus.Pending, decision.Status);
        Assert.Null(decision.EncryptedReason);
        Assert.Equal("manual_review", decision.ReasonCode);
    }

    [Fact]
    public void Create_confirmed_risk_requires_reason()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.ConfirmedRisk, "confirmed", null,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Create_confirmed_risk_with_reason_succeeds()
    {
        var reason = new string('x', 100);

        var decision = ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.ConfirmedRisk, "confirmed", reason,
            "sid", DateTimeOffset.UtcNow);

        Assert.Equal(ReviewStatus.ConfirmedRisk, decision.Status);
        Assert.Equal(reason, decision.EncryptedReason);
    }

    [Fact]
    public void Reason_must_be_at_least_one_character()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.ConfirmedRisk, "confirmed", "",
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Reason_must_not_exceed_2000_characters()
    {
        var tooLong = new string('x', 2001);

        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.FalsePositive, "fp", tooLong,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Reason_exactly_2000_characters_is_accepted()
    {
        var reason = new string('x', 2000);

        var decision = ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.FalsePositive, "fp", reason,
            "sid", DateTimeOffset.UtcNow);

        Assert.Equal(reason, decision.EncryptedReason);
    }

    [Fact]
    public void ApprovedException_requires_reason()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.ApprovedException, "exception", null,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void RemediatedAwaitingRescan_requires_reason()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.RemediatedAwaitingRescan, "remediated", null,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void At_least_group_or_occurrence_must_be_provided()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, null,
            ReviewStatus.Pending, "code", null,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Group_level_decision_is_valid()
    {
        var groupId = new FindingGroupId(Guid.NewGuid());

        var decision = ReviewDecision.Create(
            SampleScanId, groupId, null,
            ReviewStatus.Pending, "group_review", null,
            "sid", DateTimeOffset.UtcNow);

        Assert.Equal(groupId, decision.GroupId);
        Assert.Null(decision.OccurrenceId);
    }

    [Fact]
    public void Each_decision_has_unique_id()
    {
        var d1 = ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.Pending, "c1", null, "sid", DateTimeOffset.UtcNow);

        var d2 = ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.Pending, "c2", null, "sid", DateTimeOffset.UtcNow);

        Assert.NotEqual(d1.Id, d2.Id);
    }

    [Fact]
    public void Rejects_empty_reason_code()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.Pending, "", null,
            "sid", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rejects_empty_user_sid_hmac()
    {
        Assert.Throws<ArgumentException>(() => ReviewDecision.Create(
            SampleScanId, null, SampleOccurrenceId,
            ReviewStatus.Pending, "code", null,
            "", DateTimeOffset.UtcNow));
    }
}
