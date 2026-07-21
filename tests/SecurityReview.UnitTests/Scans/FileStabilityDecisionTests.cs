using SecurityReview.Application.Scans.Inventory;

namespace SecurityReview.UnitTests.Scans;

public sealed class FileStabilityDecisionTests
{
    [Theory]
    [InlineData(true, 0, false, FileStabilityAction.MarkUnstable)]
    [InlineData(true, 5, false, FileStabilityAction.MarkUnstable)]
    [InlineData(false, 0, false, FileStabilityAction.MarkUnstable)]
    [InlineData(true, 0, true, FileStabilityAction.Accept)]
    [InlineData(false, 0, true, FileStabilityAction.RescanOnce)]
    [InlineData(false, 1, true, FileStabilityAction.MarkUnstable)]
    public void Decide_chooses_bounded_mutation_action(bool hashesEqual, int priorRetries,
        bool identityPreserved, FileStabilityAction expected)
    {
        Assert.Equal(expected, FileStabilityDecision.Decide(hashesEqual, priorRetries, identityPreserved));
    }

    [Fact]
    public void Decide_identity_changed_marks_unstable_regardless_of_hash_or_retries()
    {
        Assert.Equal(FileStabilityAction.MarkUnstable,
            FileStabilityDecision.Decide(hashesEqual: true, priorRetries: 0, identityPreserved: false));
        Assert.Equal(FileStabilityAction.MarkUnstable,
            FileStabilityDecision.Decide(hashesEqual: false, priorRetries: 5, identityPreserved: false));
    }

    [Fact]
    public void Decide_prior_retries_greater_than_one_still_marks_unstable()
    {
        Assert.Equal(FileStabilityAction.MarkUnstable,
            FileStabilityDecision.Decide(false, priorRetries: 5, identityPreserved: true));
    }

    [Fact]
    public void Decide_hashes_equal_always_accepts_regardless_of_prior_retries()
    {
        Assert.Equal(FileStabilityAction.Accept,
            FileStabilityDecision.Decide(true, priorRetries: 5, identityPreserved: true));
    }
}
