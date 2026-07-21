namespace SecurityReview.UnitTests.Oci;

using SecurityReview.Parsers.Oci;

public sealed class OciDigestTests
{
    [Fact]
    public void parse_valid_lowercase_digest_succeeds()
    {
        string input = "sha256:" + new string('a', 64);
        var digest = OciDigest.Parse(input);
        Assert.Equal(input, digest.Value);
        Assert.Equal(32, digest.Hash.Length);
    }

    [Fact]
    public void parse_with_mixed_numbers_and_letters_succeeds()
    {
        string hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        string input = "sha256:" + hex;
        var digest = OciDigest.Parse(input);
        Assert.Equal(input, digest.Value);
    }

    [Fact]
    public void parse_null_throws()
    {
        var ex = Assert.Throws<FormatException>(() => OciDigest.Parse(null!));
        Assert.Contains("null", ex.Message);
    }

    [Fact]
    public void parse_empty_string_throws()
    {
        var ex = Assert.Throws<FormatException>(() => OciDigest.Parse(""));
        Assert.Contains("sha256:", ex.Message);
    }

    [Fact]
    public void parse_wrong_prefix_throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            OciDigest.Parse("md5:" + new string('a', 32)));
        Assert.Contains("sha256:", ex.Message);
    }

    [Fact]
    public void parse_uppercase_hex_rejected()
    {
        string input = "sha256:" + new string('A', 64);
        Assert.False(OciDigest.TryParse(input, out _, out string? error));
        Assert.Contains("invalid hex", error);
    }

    [Fact]
    public void parse_mixed_case_rejected()
    {
        string input = "sha256:" + new string('a', 32) + new string('B', 32);
        Assert.False(OciDigest.TryParse(input, out _, out string? error));
        Assert.Contains("invalid hex", error);
    }

    [Fact]
    public void parse_wrong_length_63_chars_throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            OciDigest.Parse("sha256:" + new string('a', 63)));
        Assert.Contains("64 hex", ex.Message);
    }

    [Fact]
    public void parse_wrong_length_65_chars_throws()
    {
        var ex = Assert.Throws<FormatException>(() =>
            OciDigest.Parse("sha256:" + new string('a', 65)));
        Assert.Contains("64 hex", ex.Message);
    }

    [Fact]
    public void parse_non_hex_characters_rejected()
    {
        Assert.False(OciDigest.TryParse(
            "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            out _, out string? error));
        Assert.Contains("invalid hex", error);
    }

    [Fact]
    public void fixed_time_equals_same_value_returns_true()
    {
        string hex = new string('f', 64);
        var d1 = OciDigest.Parse("sha256:" + hex);
        var d2 = OciDigest.Parse("sha256:" + hex);
        Assert.True(d1.Equals(d2));
        Assert.True(d1 == d2);
    }

    [Fact]
    public void fixed_time_equals_different_value_returns_false()
    {
        var d1 = OciDigest.Parse("sha256:" + new string('a', 64));
        var d2 = OciDigest.Parse("sha256:" + new string('b', 64));
        Assert.False(d1.Equals(d2));
        Assert.True(d1 != d2);
    }

    [Fact]
    public void equals_null_returns_false()
    {
        var d = OciDigest.Parse("sha256:" + new string('a', 64));
        Assert.False(d.Equals(null));
    }

    [Fact]
    public void get_hash_code_is_stable()
    {
        var d = OciDigest.Parse("sha256:" + new string('a', 64));
        int h1 = d.GetHashCode();
        int h2 = d.GetHashCode();
        Assert.Equal(h1, h2);
    }

    [Fact]
    public void to_string_returns_canonical_form()
    {
        string input = "sha256:" + new string('a', 64);
        var d = OciDigest.Parse(input);
        Assert.Equal(input, d.ToString());
    }

    [Fact]
    public void compute_produces_valid_sha256()
    {
        var d = OciDigest.Compute("hello"u8);
        Assert.StartsWith("sha256:", d.Value);
        Assert.Equal(32, d.Hash.Length);
    }

    [Fact]
    public void compute_empty_data_is_known()
    {
        var d = OciDigest.Compute(Array.Empty<byte>());
        Assert.Equal(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            d.Value);
    }

    [Fact]
    public void from_hash_rejects_wrong_size()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OciDigest.FromHash(new byte[31]));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void try_parse_null_returns_false()
    {
        Assert.False(OciDigest.TryParse(null!, out _, out string? error));
        Assert.Contains("null", error);
    }

    [Fact]
    public void try_parse_empty_returns_false()
    {
        Assert.False(OciDigest.TryParse("", out _, out string? error));
        Assert.NotNull(error);
    }
}
