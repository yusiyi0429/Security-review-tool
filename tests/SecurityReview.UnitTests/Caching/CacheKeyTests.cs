namespace SecurityReview.UnitTests.Caching;

using SecurityReview.Application.Caching;

public sealed class CacheKeyTests
{
    // ---------------------------------------------------------------
    // ParseCacheKey tests
    // ---------------------------------------------------------------

    [Fact]
    public void ParseCacheKey_IdenticalInputs_YieldsIdenticalKeys()
    {
        var a = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001",
            "spreadsheet-v1",
            "2.0.1",
            "default-1mb-60s",
            "contract-v3");
        var b = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001",
            "spreadsheet-v1",
            "2.0.1",
            "default-1mb-60s",
            "contract-v3");

        Assert.Equal(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentFileSha256_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var b = new ParseCacheKey(
            "bbb0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentStreamIdentity_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var b = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-002",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentParserId_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var b = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "pdf-v2", "2.0.1", "default", "contract-v3");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentParserVersion_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var b = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.2", "default", "contract-v3");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentLimitsProfile_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default-1mb-60s", "contract-v3");
        var b = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "large-10mb-300s", "contract-v3");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_DifferentContractVersion_YieldsDifferentKey()
    {
        var a = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var b = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v4");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void ParseCacheKey_KeyIsLowercaseHex()
    {
        var key = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        Assert.Matches("^[a-f0-9]{64}$", key.Key);
    }

    [Fact]
    public void ParseCacheKey_EmptyComponent_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentException>(() => new ParseCacheKey(
            "", "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3"));
    }

    [Fact]
    public void ParseCacheKey_KeyIsDeterministic()
    {
        var key = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001",
            "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        // Key should be a 64-char lowercase hex string (SHA-256).
        Assert.Equal(64, key.Key.Length);
        // Each call returns the same value (Lazy).
        Assert.Equal(key.Key, key.Key);
    }

    // ---------------------------------------------------------------
    // DetectionCacheKey tests
    // ---------------------------------------------------------------

    [Fact]
    public void DetectionCacheKey_IdenticalInputs_YieldsIdenticalKeys()
    {
        var parseKey = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        var a = new DetectionCacheKey(parseKey,
            "policy-sha256-00000000000000000000000000000000000000000000",
            "bundle-4.2.0");
        var b = new DetectionCacheKey(parseKey,
            "policy-sha256-00000000000000000000000000000000000000000000",
            "bundle-4.2.0");

        Assert.Equal(a.Key, b.Key);
    }

    [Fact]
    public void DetectionCacheKey_DifferentParseKey_YieldsDifferentKey()
    {
        var parseA = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var parseB = new ParseCacheKey(
            "bbb0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        var a = new DetectionCacheKey(parseA,
            "policy-sha256-00000000000000000000000000000000000000000000",
            "bundle-4.2.0");
        var b = new DetectionCacheKey(parseB,
            "policy-sha256-00000000000000000000000000000000000000000000",
            "bundle-4.2.0");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void DetectionCacheKey_DifferentPolicySha256_YieldsDifferentKey()
    {
        var parse = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        var a = new DetectionCacheKey(parse, "policy-v1-hash", "bundle-4.2.0");
        var b = new DetectionCacheKey(parse, "policy-v2-hash", "bundle-4.2.0");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void DetectionCacheKey_DifferentDetectorBundle_YieldsDifferentKey()
    {
        var parse = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        var a = new DetectionCacheKey(parse, "policy-hash", "bundle-4.2.0");
        var b = new DetectionCacheKey(parse, "policy-hash", "bundle-4.3.0");

        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public void DetectionCacheKey_KeyIsLowercaseHex()
    {
        var parse = new ParseCacheKey(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var key = new DetectionCacheKey(parse, "policy-hash", "bundle-4.2.0");

        Assert.Matches("^[a-f0-9]{64}$", key.Key);
    }

    // ---------------------------------------------------------------
    // SemanticCacheKey tests
    // ---------------------------------------------------------------

    [Fact]
    public void SemanticCacheKey_IdenticalInputs_YieldsIdenticalKeys()
    {
        var a = new SemanticCacheKey(
            "candidate-hmac-value-00000000000000000000000000000000000001",
            "context-sha256-value-000000000000000000000000000000000000002",
            "endpoint-fingerprint-003",
            "gpt-4o",
            "json_object",
            "low",
            "prompt-hash-004",
            "rule-pack-hash-005",
            "adapter-v1.0");
        var b = new SemanticCacheKey(
            "candidate-hmac-value-00000000000000000000000000000000000001",
            "context-sha256-value-000000000000000000000000000000000000002",
            "endpoint-fingerprint-003",
            "gpt-4o",
            "json_object",
            "low",
            "prompt-hash-004",
            "rule-pack-hash-005",
            "adapter-v1.0");

        Assert.Equal(a.Key, b.Key);
    }

    [Fact]
    public void SemanticCacheKey_EachComponentChange_InvalidatesKey()
    {
        var reference = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");

        // Candidate HMAC change
        var diff1 = new SemanticCacheKey(
            "diff-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff1.Key);

        // Context SHA-256 change
        var diff2 = new SemanticCacheKey(
            "ref-hmac", "diff-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff2.Key);

        // Endpoint change
        var diff3 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "diff-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff3.Key);

        // Model change
        var diff4 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4-turbo", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff4.Key);

        // Response format change
        var diff5 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "text", "low",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff5.Key);

        // Temperature change
        var diff6 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "high",
            "ref-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff6.Key);

        // Prompt hash change
        var diff7 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "diff-prompt", "ref-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff7.Key);

        // Rule-pack hash change
        var diff8 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "diff-rp-hash", "v1.0");
        Assert.NotEqual(reference.Key, diff8.Key);

        // Adapter version change
        var diff9 = new SemanticCacheKey(
            "ref-hmac", "ref-ctx-hash", "ref-ep",
            "gpt-4o", "json_object", "low",
            "ref-prompt", "ref-rp-hash", "v2.0");
        Assert.NotEqual(reference.Key, diff9.Key);
    }

    [Fact]
    public void SemanticCacheKey_KeyIsLowercaseHex()
    {
        var key = new SemanticCacheKey(
            "hmac", "ctx-hash", "ep",
            "model", "format", "temp",
            "prompt", "rp-hash", "v1.0");

        Assert.Matches("^[a-f0-9]{64}$", key.Key);
    }

    [Fact]
    public void SemanticCacheKey_AllComponentsRequired()
    {
        Assert.Throws<ArgumentException>(() => new SemanticCacheKey(
            "", "ctx", "ep", "model", "fmt", "tmp", "p", "rp", "v"));
        Assert.Throws<ArgumentException>(() => new SemanticCacheKey(
            "hmac", "", "ep", "model", "fmt", "tmp", "p", "rp", "v"));
        Assert.Throws<ArgumentException>(() => new SemanticCacheKey(
            "hmac", "ctx", "", "model", "fmt", "tmp", "p", "rp", "v"));
    }

    // ---------------------------------------------------------------
    // Composite invalidation: changing ParseKey invalidates DetectionKey
    // ---------------------------------------------------------------

    [Fact]
    public void DetectionCacheKey_ChangingParseKeyInvalidatesDetectionKey()
    {
        var parse1 = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var parse2 = new ParseCacheKey(
            "aaa0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");

        // Same parse material, but different instance — keys should be equal.
        Assert.Equal(parse1.Key, parse2.Key);

        var detect1 = new DetectionCacheKey(parse1, "policy-hash", "bundle-1.0");
        var detect2 = new DetectionCacheKey(parse2, "policy-hash", "bundle-1.0");
        Assert.Equal(detect1.Key, detect2.Key);

        // Now change one parse component and verify detection key changes.
        var parse3 = new ParseCacheKey(
            "bbb0000000000000000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "contract-v3");
        var detect3 = new DetectionCacheKey(parse3, "policy-hash", "bundle-1.0");
        Assert.NotEqual(detect1.Key, detect3.Key);
    }
}
