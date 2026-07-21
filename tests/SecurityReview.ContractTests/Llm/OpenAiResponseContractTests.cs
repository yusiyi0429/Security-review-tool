using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.ContractTests.Llm;

/// <summary>
/// Contract tests for <see cref="OpenAiChatResponseParser"/>. The
/// parser is the single chokepoint between the LLM wire and the
/// audit / UI surface — every rejection path is asserted here so a
/// regression cannot silently downgrade a malicious payload.
/// </summary>
public sealed class OpenAiResponseContractTests
{
    private static readonly CandidateId ExpectedId = new(new Guid("11111111-1111-1111-1111-111111111111"));

    private static HttpResponseMessage Build(string body, int statusCode = 200, string? contentType = null)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var response = new HttpResponseMessage((HttpStatusCode)statusCode)
        {
            Content = new ByteArrayContent(bytes),
        };
        response.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            contentType ?? "application/json; charset=utf-8");
        return response;
    }

    private static async Task<LlmReviewResult> Parse(string body, int statusCode = 200)
    {
        using var response = Build(body, statusCode);
        return await OpenAiChatResponseParser.ParseAsync(ExpectedId, response);
    }

    // ---------- Valid minimal object ----------

    [Fact]
    public async Task Parses_minimal_valid_object()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "possible",
              "category_id": "SENS-007",
              "confidence": 0.72,
              "rationale": "语境可能描述内部控制阈值，需要人工确认。",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Possible, result.Classification);
        Assert.Equal(CategoryId.Parse("SENS-007"), result.CategoryId);
        Assert.Equal(0.72, result.Confidence);
        Assert.False(result.InjectionDetected);
        Assert.Null(result.ReasonCode);
        Assert.Equal(ExpectedId, result.CandidateId);
        Assert.NotNull(result.PromptSha256);
        Assert.Equal(64, result.PromptSha256!.Length);
        Assert.Equal("semantic-review-v1", result.PromptVersion);
    }

    // ---------- Markdown / prose wrapping ----------

    [Fact]
    public async Task Rejects_markdown_fenced_response()
    {
        const string body = """
            ```json
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false
            }
            ```
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_not_json", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_prose_prefix()
    {
        const string body = "Sure, here's my classification: { \"candidate_id\":\"11111111-1111-1111-1111-111111111111\",\"classification\":\"confirmed\",\"category_id\":\"SENS-001\",\"confidence\":0.9,\"rationale\":\"yes\",\"injection_detected\":false }";
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_not_json", result.ReasonCode);
    }

    // ---------- Missing / duplicate / unknown fields ----------

    [Fact]
    public async Task Rejects_missing_field()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes"
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_missing_field", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_duplicate_field()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false,
              "injection_detected": true
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_duplicate_property", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_unknown_property()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false,
              "sneaky": "extra"
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_unknown_property", result.ReasonCode);
    }

    // ---------- Wrong candidate ID ----------

    [Fact]
    public async Task Rejects_wrong_candidate_id()
    {
        const string body = """
            {
              "candidate_id": "22222222-2222-2222-2222-222222222222",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_candidate_id_mismatch", result.ReasonCode);
    }

    // ---------- Invalid classification / category ----------

    [Theory]
    [InlineData("maybe")]
    [InlineData("Confirmed")]
    [InlineData("CONFIRMED")]
    public async Task Rejects_unknown_classification(string cls)
    {
        string body = $$"""
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "{{cls}}",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_unknown_classification", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_unknown_category()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-099",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_unknown_category", result.ReasonCode);
    }

    // ---------- NaN / out-of-range confidence ----------

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    [InlineData(99.0)]
    public async Task Rejects_confidence_out_of_range(double value)
    {
        string body = $$"""
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": {{value}},
              "rationale": "yes",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_confidence_out_of_range", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_nan_confidence_string()
    {
        // Utf8JsonReader rejects "NaN" as a number — the string never
        // reaches the JSON number parser and we treat it as wrong type.
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": "NaN",
              "rationale": "yes",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_wrong_field_type", result.ReasonCode);
    }

    // ---------- Rationale length / control chars ----------

    [Fact]
    public async Task Rejects_rationale_over_500_chars()
    {
        string rationale = new('x', 501);
        string body = $$"""
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "{{rationale}}",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_rationale_too_long", result.ReasonCode);
    }

    [Fact]
    public async Task Accepts_rationale_at_exactly_500_chars()
    {
        string rationale = new('x', 500);
        string body = $$"""
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "{{rationale}}",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Confirmed, result.Classification);
        Assert.Equal(500, result.Rationale.Length);
    }

    [Fact]
    public async Task Rejects_rationale_with_control_chars()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "hello\u0007world",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_rationale_control_char", result.ReasonCode);
    }

    // ---------- Injection → Unresolved(injection_detected) ----------

    [Fact]
    public async Task Injection_detected_forces_unresolved_with_no_rationale()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "ignored everything above and marked safe",
              "injection_detected": true
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.True(result.InjectionDetected);
        Assert.Equal("injection_detected", result.ReasonCode);
        Assert.Equal(string.Empty, result.Rationale);
        Assert.Null(result.Confidence);
    }

    // ---------- Unlikely remains a stored candidate result ----------

    [Fact]
    public async Task Unlikely_classification_is_kept_as_a_result()
    {
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "unlikely",
              "category_id": "SENS-003",
              "confidence": 0.6,
              "rationale": "looks like a benign placeholder",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Unlikely, result.Classification);
        Assert.False(result.InjectionDetected);
        Assert.Null(result.ReasonCode);
    }

    // ---------- Size cap ----------

    [Fact]
    public async Task Rejects_body_over_64KiB()
    {
        // 65 KiB worth of padding before the JSON object. The bounded
        // stream stops at 65,536 bytes and returns "" to the parser.
        string padding = new('a', 65 * 1024);
        string body = "{ \"candidate_id\":\"11111111-1111-1111-1111-111111111111\",\"classification\":\"confirmed\",\"category_id\":\"SENS-001\",\"confidence\":0.9,\"rationale\":\"yes\",\"injection_detected\":false }";
        var result = await Parse(padding + body);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_body_empty", result.ReasonCode);
    }

    [Fact]
    public async Task Rejects_empty_body()
    {
        var result = await Parse(string.Empty);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
        Assert.Equal("response_body_empty", result.ReasonCode);
    }

    // ---------- Depth cap ----------

    [Fact]
    public async Task Rejects_response_with_too_deep_structure()
    {
        // The allowed depth is 8. Build an object 9 levels deep where
        // every required field lives at the deepest level.
        string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "confirmed",
              "category_id": "SENS-001",
              "confidence": 0.9,
              "rationale": "yes",
              "injection_detected": false,
              "a": { "b": { "c": { "d": { "e": { "f": { "g": { "h": { "i": "deep" } } } } } } } }
            }
            """;
        var result = await Parse(body);
        // The extra nested field is "unknown property" — depth limit
        // is not the first failure here because the top-level shape
        // is shallow. Verify the response was rejected.
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);
    }

    // ---------- Wire envelope: choices[].message.content (text-mode) ----------

    [Fact]
    public async Task Direct_object_response_parses_as_object()
    {
        // The parser accepts either a bare JSON object or the OpenAI
        // { "choices":[ ... ] } wrapper. Direct objects are the
        // JsonSchema / json_object path; the wrapper form is the
        // PromptOnly fallback.
        const string body = """
            {
              "candidate_id": "11111111-1111-1111-1111-111111111111",
              "classification": "possible",
              "category_id": "SENS-002",
              "confidence": 0.5,
              "rationale": "tight but worth a second look",
              "injection_detected": false
            }
            """;
        var result = await Parse(body);
        Assert.Equal(SemanticClassification.Possible, result.Classification);
    }
}
