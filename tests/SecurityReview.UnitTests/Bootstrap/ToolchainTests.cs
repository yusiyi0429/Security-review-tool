namespace SecurityReview.UnitTests.Bootstrap;

public sealed class ToolchainTests
{
    [Fact]
    public void Runtime_major_is_ten() => Assert.Equal(10, Environment.Version.Major);
}
