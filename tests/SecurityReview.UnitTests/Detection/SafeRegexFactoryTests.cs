using System.Text.RegularExpressions;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class SafeRegexFactoryTests
{
    [Fact]
    public void Create_accepts_simple_pattern()
    {
        Regex regex = SafeRegexFactory.Create(@"\d{3}-\d{4}");

        Assert.Matches(regex.ToString(), "123-4567");
        Assert.DoesNotMatch(regex.ToString(), "abc-defg");
    }

    [Fact]
    public void Create_rejects_empty_pattern()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(""));
    }

    [Fact]
    public void Create_rejects_null_pattern()
    {
        Assert.Throws<ArgumentNullException>(() => SafeRegexFactory.Create(null!));
    }

    [Fact]
    public void Create_rejects_pattern_exceeding_max_length()
    {
        string longPattern = new('a', SafeRegexFactory.MaxPatternLength + 1);
        var ex = Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(longPattern));
        Assert.Contains("exceeds maximum", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_lookahead()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"foo(?=bar)"));
    }

    [Fact]
    public void Create_rejects_negative_lookahead()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"foo(?!bar)"));
    }

    [Fact]
    public void Create_rejects_lookbehind()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(?<=foo)bar"));
    }

    [Fact]
    public void Create_rejects_negative_lookbehind()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(?<!foo)bar"));
    }

    [Fact]
    public void Create_rejects_backreference()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(.)\1"));
    }

    [Fact]
    public void Create_rejects_named_backreference()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(?<x>.)\k<x>"));
    }

    [Fact]
    public void Create_rejects_conditional()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(?(1)yes|no)"));
    }

    [Fact]
    public void Create_rejects_balancing_group()
    {
        Assert.Throws<ArgumentException>(() => SafeRegexFactory.Create(@"(?<a-b>foo)"));
    }

    [Fact]
    public void Create_compiles_with_nonbacktracking()
    {
        Regex regex = SafeRegexFactory.Create(@"hello");

        Assert.Equal(RegexOptions.NonBacktracking | RegexOptions.CultureInvariant,
            regex.Options & (RegexOptions.NonBacktracking | RegexOptions.CultureInvariant));
    }

    [Fact]
    public void Create_has_100ms_timeout()
    {
        Regex regex = SafeRegexFactory.Create(@"hello");
        Assert.Equal(TimeSpan.FromMilliseconds(100), regex.MatchTimeout);
    }

    [Fact]
    public void CreateBuiltIn_uses_25ms_timeout()
    {
        Regex regex = SafeRegexFactory.CreateBuiltIn(@"builtin-test-phone");
        Assert.Equal(TimeSpan.FromMilliseconds(25), regex.MatchTimeout);
    }

    [Fact]
    public void CreateBuiltIn_throws_for_unregistered_pattern()
    {
        Assert.Throws<InvalidOperationException>(
            () => SafeRegexFactory.CreateBuiltIn(@"not-a-registered-builtin"));
    }

    [Fact]
    public void CreateBuiltIn_registered_pattern_works()
    {
        Regex regex = SafeRegexFactory.CreateBuiltIn(@"builtin-test-phone");
        Assert.Matches(regex.ToString(), "123-4567");
    }

    [Fact]
    public void pattern_at_max_length_is_accepted()
    {
        string pattern = new('a', SafeRegexFactory.MaxPatternLength);
        Regex regex = SafeRegexFactory.Create(pattern);
        Assert.NotNull(regex);
    }

    [Fact]
    public void worst_case_builtin_completes_under_timeout()
    {
        Regex regex = SafeRegexFactory.CreateBuiltIn(@"builtin-test-phone");
        string input = new('0', 10_000);

        bool matched = regex.IsMatch(input);
        // Assertion: simply verifying no timeout exception is thrown
        Assert.True(true);
    }
}
