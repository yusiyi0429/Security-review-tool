using SecurityReview.Application.Scans.Inventory;

namespace SecurityReview.UnitTests.Scans;

public sealed class FileStabilityDecisionTests
{
    [Theory]
    [InlineData(true, 0, FileStabilityAction.Accept)]
    [InlineData(false, 0, FileStabilityAction.RescanOnce)]
    [InlineData(false, 1, FileStabilityAction.MarkUnstable)]
    public void Decide_chooses_bounded_mutation_action(bool hashesEqual, int priorRetries,
        FileStabilityAction expected)
    {
        Assert.Equal(expected, FileStabilityDecision.Decide(hashesEqual, priorRetries));
    }

    [Fact]
    public void Decide_prior_retries_greater_than_one_still_marks_unstable()
    {
        Assert.Equal(FileStabilityAction.MarkUnstable,
            FileStabilityDecision.Decide(false, priorRetries: 5));
    }

    [Fact]
    public void Decide_hashes_equal_always_accepts_regardless_of_prior_retries()
    {
        Assert.Equal(FileStabilityAction.Accept,
            FileStabilityDecision.Decide(true, priorRetries: 5));
    }
}
