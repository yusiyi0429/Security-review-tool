using SecurityReview.Domain.Llm;

namespace SecurityReview.UnitTests.Llm;

/// <summary>
/// Validation tests for <see cref="LlmEndpointOptions"/>: HTTPS-only,
/// no userinfo/fragment/query in base URL, no wildcards/relative paths,
/// no CR/LF, base-path enforcement for chat completions, timeout/concurrency
/// bounds, model length, response-format mode, and custom-header name rules.
/// </summary>
public sealed class LlmEndpointOptionsTests
{
    private const string Model = "gpt-test-model";
    private const string Reference = "Llm.Endpoint.Default";

    // ---------- Valid HTTPS base URL ----------

    [Fact]
    public void Accepts_https_hostname_with_default_port()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference);
        Assert.Equal(new Uri("https://llm.internal.example/"), options.BaseUri);
        Assert.Equal(new Uri("https://llm.internal.example"), options.ApprovedOrigin);
    }

    [Fact]
    public void Accepts_https_ip_with_non_default_port_and_base_path()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://10.0.0.5:8443/llm/"),
            chatCompletionsPath: "/llm/v1/chat/completions",
            model: Model,
            reference: Reference);
        Assert.Equal(8443, options.BaseUri.Port);
        Assert.Equal(new Uri("https://10.0.0.5:8443"), options.ApprovedOrigin);
    }

    [Fact]
    public void Accepts_loopback_http_in_debug_with_allow_loopback()
    {
#if DEBUG
        var options = LlmEndpointOptions.Create(
            new Uri("http://127.0.0.1:9000/llm/"),
            chatCompletionsPath: "/llm/v1/chat/completions",
            model: Model,
            reference: Reference,
            allowLoopbackHttp: true);
        Assert.Equal("http", options.BaseUri.Scheme);
        Assert.Equal("127.0.0.1", options.ApprovedOrigin.Host);
#endif
    }

    // ---------- HTTP / scheme rejected in release ----------

    [Fact]
    public void Rejects_http_in_release()
    {
        var ex = Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("http://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
        Assert.Contains("https", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_unsupported_scheme()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("ftp://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    // ---------- Userinfo / fragment / query ----------

    [Fact]
    public void Rejects_userinfo_in_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://user:pass@llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_fragment_in_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/#frag"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_query_in_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/?token=abc"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_embedded_credentials_in_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://user@llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    // ---------- Wildcards / relative / unsupported hosts ----------

    [Fact]
    public void Rejects_wildcard_host()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://*.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_relative_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("/llm/", UriKind.Relative),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_empty_host()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https:///path"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_oversize_url_over_2048_chars()
    {
        string host = new('a', 2100);
        var uri = new Uri($"https://{host}/");
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            uri,
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    // ---------- CR / LF ----------

    [Fact]
    public void Rejects_cr_in_base_url()
    {
        // CR/LF cannot appear in a Uri value normally — but the
        // chat completions path may come from configuration. Test
        // path-level CR/LF rejection as the attack surface.
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions\r\nInjected: yes",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_lf_in_base_url()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions\nInjected: yes",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_path_traversal_in_chat_completions_path()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/llm/"),
            chatCompletionsPath: "/../etc/passwd",
            model: Model,
            reference: Reference));
    }

    // ---------- Chat completions path ----------

    [Fact]
    public void Defaults_chat_completions_path()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference);
        Assert.Equal("/v1/chat/completions", options.ChatCompletionsPath);
    }

    [Fact]
    public void Chat_completions_path_must_be_root_relative()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    [Fact]
    public void Chat_completions_path_must_remain_under_base_path()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/llm/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference));
    }

    // ---------- Model ----------

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Rejects_empty_or_whitespace_model(string model)
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_model_over_256_chars()
    {
        string model = new('a', 257);
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: model,
            reference: Reference));
    }

    [Fact]
    public void Rejects_control_chars_in_model()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: "model\twith\tcontrol",
            reference: Reference));
    }

    [Fact]
    public void Accepts_model_at_256_chars()
    {
        string model = new('a', 256);
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: model,
            reference: Reference);
        Assert.Equal(256, options.Model.Length);
    }

    // ---------- Response format mode ----------

    [Fact]
    public void Defaults_response_format_mode_to_json_schema()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference);
        Assert.Equal(LlmResponseFormatMode.JsonSchema, options.ResponseFormatMode);
    }

    [Fact]
    public void Defaults_send_temperature_zero_to_true()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference);
        Assert.True(options.SendTemperatureZero);
    }

    [Fact]
    public void Accepts_response_format_json_object()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference,
            responseFormatMode: LlmResponseFormatMode.JsonObject);
        Assert.Equal(LlmResponseFormatMode.JsonObject, options.ResponseFormatMode);
    }

    [Fact]
    public void Accepts_response_format_prompt_only()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference,
            responseFormatMode: LlmResponseFormatMode.PromptOnly);
        Assert.Equal(LlmResponseFormatMode.PromptOnly, options.ResponseFormatMode);
    }

    [Fact]
    public void Rejects_invalid_response_format_value()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference,
            responseFormatMode: (LlmResponseFormatMode)999));
    }

    // ---------- Auth mode ----------

    [Fact]
    public void Defaults_auth_mode_to_none()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference);
        Assert.Equal(LlmAuthMode.None, options.AuthMode);
        Assert.Null(options.CustomHeaderName);
    }

    [Fact]
    public void Accepts_bearer_without_custom_header()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.Bearer);
        Assert.Equal(LlmAuthMode.Bearer, options.AuthMode);
    }

    [Fact]
    public void Rejects_custom_header_name_when_auth_none()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.None,
            customHeaderName: "X-Tenant"));
    }

    [Fact]
    public void Rejects_custom_header_name_when_auth_bearer()
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.Bearer,
            customHeaderName: "X-Tenant"));
    }

    [Theory]
    [InlineData("Host")]
    [InlineData("host")]
    [InlineData("Content-Length")]
    [InlineData("Connection")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Proxy-Connection")]
    [InlineData("Forwarded")]
    [InlineData("X-Forwarded-For")]
    [InlineData("X-Forwarded-Host")]
    public void Rejects_forbidden_custom_header_names(string header)
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.CustomHeader,
            customHeaderName: header));
    }

    [Theory]
    [InlineData("X-Api-Key")]
    [InlineData("api-key")]
    [InlineData("X-Tenant-Id")]
    public void Accepts_valid_custom_header_names(string header)
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.CustomHeader,
            customHeaderName: header);
        Assert.Equal(header, options.CustomHeaderName);
    }

    [Theory]
    [InlineData("X Header")]
    [InlineData("X:Header")]
    [InlineData("X\tHeader")]
    [InlineData("X\nHeader")]
    [InlineData("")]
    public void Rejects_invalid_custom_header_token(string header)
    {
        Assert.Throws<ArgumentException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.CustomHeader,
            customHeaderName: header));
    }

    // ---------- Timeout / concurrency ----------

    [Fact]
    public void Defaults_timeout_30s_and_max_concurrency_2()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference);
        Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
        Assert.Equal(2, options.MaxConcurrency);
    }

    [Fact]
    public void Rejects_timeout_below_1s_or_above_120s()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            timeout: TimeSpan.FromMilliseconds(500)));
        Assert.Throws<ArgumentOutOfRangeException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            timeout: TimeSpan.FromSeconds(121)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(-1)]
    public void Rejects_max_concurrency_outside_1_to_4(int concurrency)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            maxConcurrency: concurrency));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void Accepts_max_concurrency_1_to_4(int concurrency)
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            model: Model,
            reference: Reference,
            maxConcurrency: concurrency);
        Assert.Equal(concurrency, options.MaxConcurrency);
    }

    // ---------- Privacy ----------

    [Fact]
    public void ToString_does_not_leak_model_or_host()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: Model,
            reference: Reference,
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default");
        string text = options.ToString();
        Assert.DoesNotContain("llm.internal.example", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Model, text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Llm.Credential.Default", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Approved_origin_is_authority_only()
    {
        var options = LlmEndpointOptions.Create(
            new Uri("https://llm.internal.example:8443/llm/v1/"),
            chatCompletionsPath: "/llm/v1/chat/completions",
            model: Model,
            reference: Reference);
        Assert.Equal("llm.internal.example:8443", options.ApprovedOrigin.Authority);
        Assert.Equal(string.Empty, options.ApprovedOrigin.AbsolutePath);
    }
}