using SecurityReview.Domain;
using SecurityReview.Domain.Reviews;

namespace SecurityReview.UnitTests.Reviews;

public sealed class ExceptionBindingTests
{
    // ---------- Validation ----------

    [Fact]
    public void Create_with_all_valid_fields_succeeds()
    {
        var binding = ExceptionBinding.Create(
            "hmac-asset-001", "hmac-ver-1", "hmac-path", "hmac-loc",
            "hmac-val", "rule-hash-abc", "RULE-001");

        Assert.Equal("hmac-asset-001", binding.AssetIdHmac);
        Assert.Equal("hmac-ver-1", binding.AssetVersionHmac);
        Assert.Equal("hmac-path", binding.FilePathHmac);
        Assert.Equal("hmac-loc", binding.CanonicalLocatorHmac);
        Assert.Equal("hmac-val", binding.ValueHmac);
        Assert.Equal("rule-hash-abc", binding.RulePackHash);
        Assert.Equal("RULE-001", binding.RuleId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_asset_id_hmac(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            value!, "v", "p", "l", "val", "hash", "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_asset_version_hmac(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", value!, "p", "l", "val", "hash", "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_file_path_hmac(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", "v", value!, "l", "val", "hash", "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_canonical_locator_hmac(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", "v", "p", value!, "val", "hash", "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_value_hmac(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", "v", "p", "l", value!, "hash", "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_rule_pack_hash(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", "v", "p", "l", "val", value!, "RULE-001"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Rejects_null_or_empty_rule_id(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash", value!));
    }

    // ---------- Invalidation: changing any field produces a different binding ----------

    [Fact]
    public void Changing_asset_id_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "hmac-a1", "v", "p", "l", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "hmac-a2", "v", "p", "l", "val", "hash", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_asset_version_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "hmac-v1", "p", "l", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "hmac-v2", "p", "l", "val", "hash", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_file_path_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "hmac-p1", "l", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "hmac-p2", "l", "val", "hash", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_canonical_locator_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "p", "hmac-l1", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "p", "hmac-l2", "val", "hash", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_value_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "p", "l", "hmac-val1", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "p", "l", "hmac-val2", "hash", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_rule_pack_hash_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash-1", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash-2", "RULE-001");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Changing_rule_id_produces_different_binding()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash", "RULE-002");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Identical_fields_produce_equal_bindings()
    {
        var a = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash", "RULE-001");
        var b = ExceptionBinding.Create(
            "a", "v", "p", "l", "val", "hash", "RULE-001");

        Assert.Equal(a, b);
    }
}
