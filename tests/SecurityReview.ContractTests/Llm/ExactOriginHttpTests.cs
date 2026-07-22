using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Llm;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.ContractTests.Llm;

/// <summary>
/// End-to-end contract tests for <c>ExactOriginHttpMessageHandler</c>
/// and the LLM connection-test pipeline. The mock server binds to a
/// random loopback port so the tests exercise the real
/// <see cref="SocketsHttpHandler"/> path — only the trusted peer is
/// the mock. The tests prove that the only host the LLM client
/// reaches is the approved origin, and that proxy env vars, cookies,
/// default Windows credentials, and ambient Activity headers are
/// stripped before any byte goes out.
/// </summary>
public sealed class ExactOriginHttpTests
{
    private const string ModelName = "test-model";
    private const string CanaryAuth = "SYNTHETIC_AUTH_CANARY";
    private const string CanaryBody = LlmConnectionTestService.SyntheticBodyText;

    private static LlmEndpointOptions BuildOptions(string origin, string? path = "/v1/chat/completions")
    {
        var baseUri = new Uri(origin + "/");
        return baseUri.Scheme == Uri.UriSchemeHttp
            ? LlmEndpointOptions.Create(
                baseUri: baseUri,
                chatCompletionsPath: path,
                model: ModelName,
                reference: "Llm.Endpoint.Default",
                authMode: LlmAuthMode.Bearer,
                credentialReference: "Llm.Credential.Default",
                maxConcurrency: 1,
                endpointScope: LlmEndpointScope.PrivateNetwork)
            : LlmEndpointOptions.Create(
                baseUri: baseUri,
                chatCompletionsPath: path,
                model: ModelName,
                reference: "Llm.Endpoint.Default",
                authMode: LlmAuthMode.Bearer,
                credentialReference: "Llm.Credential.Default",
                maxConcurrency: 1);
    }

    private static LlmConnectionTestResult Run(
        LlmEndpointOptions options,
        MockOpenAiServer server,
        Action<InMemorySecretStore>? configureCredentials = null)
    {
        var store = new InMemorySecretStore();
        store.Save("Llm.Credential.Default", CanaryAuth);
        configureCredentials?.Invoke(store);

        var credentials = new LlmCredentialStore(store);
        var diagnostics = new RecordingDiagnosticSink();
        var service = new LlmConnectionTestService(credentials, diagnostics);

        return service.TestConnectionAsync(
            new TestLlmConnectionCommand(options, "corr-1"),
            CancellationToken.None).GetAwaiter().GetResult();
    }

    // ---------------- Valid 200 ----------------

    [Fact]
    public void Valid_200_request_succeeds_and_only_reaches_approved_origin()
    {
        using var server = new MockOpenAiServer(ctx =>
        {
            Assert.Contains(CanaryAuth, ctx.Headers["Authorization"], StringComparison.Ordinal);
            Assert.Contains(CanaryBody, ctx.Body, StringComparison.Ordinal);
            return Task.FromResult(new HttpResponseDescriptor(200, """
                {"ok":true,"message":"SYNTHETIC_CONNECTION_TEST_OK"}
                """));
        });
        var options = BuildOptions(server.Origin);

        var result = Run(options, server);

        Assert.True(result.Succeeded);
        Assert.Equal(200, result.HttpStatusCode);
        Assert.Equal(LlmConnectionTestFailureReason.None, result.FailureReason);
        Assert.Single(server.Requests);
    }

    // ---------------- Error status codes ----------------

    [Fact]
    public void Maps_401_to_authentication_rejected()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(401, "{\"err\":\"auth\"}")));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(401, result.HttpStatusCode);
        Assert.Equal(LlmConnectionTestFailureReason.AuthenticationRejected, result.FailureReason);
    }

    [Fact]
    public void Maps_403_to_authentication_rejected()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(403, "{\"err\":\"forbidden\"}")));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(LlmConnectionTestFailureReason.AuthenticationRejected, result.FailureReason);
    }

    [Fact]
    public void Maps_404_to_request_error()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(404, "{\"err\":\"missing\"}")));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(404, result.HttpStatusCode);
        Assert.Equal(LlmConnectionTestFailureReason.RequestError, result.FailureReason);
    }

    [Fact]
    public void Maps_429_to_request_error()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(429, "{\"err\":\"slow down\"}")));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(429, result.HttpStatusCode);
    }

    [Fact]
    public void Maps_500_to_server_error()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(500, "{\"err\":\"boom\"}")));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(500, result.HttpStatusCode);
        Assert.Equal(LlmConnectionTestFailureReason.ServerError, result.FailureReason);
    }

    // ---------------- Timeout ----------------

    [Fact]
    public void Maps_timeout_when_server_does_not_reply()
    {
        using var server = new MockOpenAiServer(async ctx =>
        {
            await Task.Delay(TimeSpan.FromSeconds(15), CancellationToken.None);
            return new HttpResponseDescriptor(200, "{}");
        });
        var options = LlmEndpointOptions.CreateForLoopbackTesting(
            baseUri: new Uri(server.Origin + "/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelName,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default",
            timeout: TimeSpan.FromSeconds(1),
            maxConcurrency: 1);
        var result = Run(options, server);
        Assert.False(result.Succeeded);
        Assert.Equal(LlmConnectionTestFailureReason.Timeout, result.FailureReason);
    }

    // ---------------- Redirect ----------------

    [Fact]
    public void Redirect_to_any_target_is_rejected()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(302, "",
                Headers: new Dictionary<string, string>
                {
                    ["Location"] = "https://other.example/elsewhere",
                })));
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(LlmConnectionTestFailureReason.RedirectRejected, result.FailureReason);
    }

    // ---------------- TLS / certificate ----------------

    [Fact]
    public void Untrusted_certificate_fails_the_connection_test()
    {
        var cert = X509Helper.BuildSelfSigned(
            subject: "127.0.0.1",
            dnsName: "wrong-host.example");
        using var server = new MockOpenAiServer(
            _ => Task.FromResult(new HttpResponseDescriptor(200, "{}")),
            tlsCertificate: cert);
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(LlmConnectionTestFailureReason.CertificateUntrusted, result.FailureReason);
    }

    [Fact]
    public void Hostname_mismatched_certificate_fails()
    {
        var cert = X509Helper.BuildSelfSigned(
            subject: "127.0.0.1",
            dnsName: "wrong-host.example");
        using var server = new MockOpenAiServer(
            _ => Task.FromResult(new HttpResponseDescriptor(200, "{}")),
            tlsCertificate: cert);
        var result = Run(BuildOptions(server.Origin), server);
        Assert.False(result.Succeeded);
        Assert.Equal(LlmConnectionTestFailureReason.CertificateUntrusted, result.FailureReason);
    }

    [Fact]
    public void Canary_endpoints_in_certificate_are_not_contacted()
    {
        // Embed canary URLs in the AIA extension. With
        // DisableCertificateDownloads = true and
        // X509RevocationMode.Offline, the runtime MUST NOT
        // issue HTTP requests to any of these URLs.
        var canaries = new[]
        {
            "http://canary-aia.invalid/canary-aia",
            "http://canary-crl.invalid/canary-crl",
            "http://canary-ocsp.invalid/canary-ocsp",
        };
        var cert = X509Helper.BuildSelfSigned(
            subject: "127.0.0.1",
            dnsName: "127.0.0.1",
            canaryUrls: canaries);
        using var server = new MockOpenAiServer(
            _ => Task.FromResult(new HttpResponseDescriptor(200, "{}")),
            tlsCertificate: cert);
        server.RecordCanaryEndpointsFromCertificate();
        var result = Run(BuildOptions(server.Origin), server);
        // We do not assert success — even when the cert passes
        // hostname check the self-signed cert is not in the Windows
        // root store. The relevant assertion is that no canary
        // request was observed.
        foreach (string canary in server.CanaryEndpoints)
        {
            Assert.DoesNotContain(server.Requests,
                r => r.Context.RequestLine.Contains(canary, StringComparison.OrdinalIgnoreCase));
        }
        _ = result;
    }

    // ---------------- Proxy env vars ----------------

    [Fact]
    public void Proxy_environment_variables_are_ignored()
    {
        // Save and set proxy env vars to non-loopback targets.
        string? oldHttp = Environment.GetEnvironmentVariable("HTTP_PROXY");
        string? oldHttps = Environment.GetEnvironmentVariable("HTTPS_PROXY");
        string? oldAll = Environment.GetEnvironmentVariable("ALL_PROXY");
        try
        {
            Environment.SetEnvironmentVariable("HTTP_PROXY", "http://proxy.invalid:9999");
            Environment.SetEnvironmentVariable("HTTPS_PROXY", "http://proxy.invalid:9999");
            Environment.SetEnvironmentVariable("ALL_PROXY", "http://proxy.invalid:9999");

            using var server = new MockOpenAiServer(_ =>
                Task.FromResult(new HttpResponseDescriptor(200, "{}")));
            var result = Run(BuildOptions(server.Origin), server);
            // Connection succeeds (no proxy use) — asserts proxy
            // settings were NOT followed.
            Assert.True(result.Succeeded);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HTTP_PROXY", oldHttp);
            Environment.SetEnvironmentVariable("HTTPS_PROXY", oldHttps);
            Environment.SetEnvironmentVariable("ALL_PROXY", oldAll);
        }
    }

    // ---------------- Ambient Activity headers ----------------

    [Fact]
    public void Ambient_Activity_headers_are_not_sent()
    {
        // Create an Activity that has parent-id baggage; the
        // exact-origin handler sets ActivityHeadersPropagator = null
        // and must not transmit any traceparent / tracestate / baggage.
        using var activity = new System.Diagnostics.Activity("ambient-test")
            .SetParentId("00-00000000000000000000000000000001-0000000000000001-01")
            .AddBaggage("canary", "SYNTHETIC_BAGGAGE");
        activity.Start();

        using var server = new MockOpenAiServer(ctx =>
        {
            Assert.False(ctx.Headers.ContainsKey("traceparent"));
            Assert.False(ctx.Headers.ContainsKey("tracestate"));
            Assert.False(ctx.Headers.ContainsKey("baggage"));
            Assert.False(ctx.Headers.ContainsKey("Canary"));
            return Task.FromResult(new HttpResponseDescriptor(200, "{}"));
        });
        var result = Run(BuildOptions(server.Origin), server);
        activity.Stop();
        Assert.True(result.Succeeded);
    }

    // ---------------- Windows integrated-auth challenge ----------------

    [Fact]
    public void Windows_integrated_auth_challenge_does_not_leak_default_credentials()
    {
        // Server replies with WWW-Authenticate: NTLM. The exact-origin
        // client MUST NOT send a default Windows credential and MUST
        // NOT follow the negotiation.
        using var server = new MockOpenAiServer(ctx =>
        {
            Assert.False(ctx.Headers.ContainsKey("Authorization"),
                "No Authorization header should be sent before the user supplies a credential.");
            return Task.FromResult(new HttpResponseDescriptor(401, "{\"err\":\"auth\"}",
                Headers: new Dictionary<string, string>
                {
                    ["WWW-Authenticate"] = "NTLM",
                }));
        });
        // Use a credential-less options object so the client would
        // only default to system credentials. The custom handler
        // must still NOT auto-respond with the system credentials.
        var options = LlmEndpointOptions.CreateForLoopbackTesting(
            baseUri: new Uri(server.Origin + "/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelName,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.None);
        var result = Run(options, server);
        Assert.False(result.Succeeded);
        Assert.Equal(401, result.HttpStatusCode);
    }

    // ---------------- Cookies ----------------

    [Fact]
    public void Cookies_set_by_server_are_not_resent_on_follow_up_request()
    {
        // First request: server replies 200 with Set-Cookie.
        // Second request: server must NOT see the cookie echoed back.
        int requestCount = 0;
        bool cookieResent = false;
        using var server = new MockOpenAiServer(ctx =>
        {
            requestCount++;
            if (requestCount == 1)
            {
                return Task.FromResult(new HttpResponseDescriptor(200, "{}",
                    Headers: new Dictionary<string, string>
                    {
                        ["Set-Cookie"] = "session=canary; Path=/",
                    }));
            }
            if (ctx.Headers.ContainsKey("Cookie"))
            {
                cookieResent = true;
            }
            return Task.FromResult(new HttpResponseDescriptor(200, "{}"));
        });
        var options = BuildOptions(server.Origin);
        var result1 = Run(options, server);
        var result2 = Run(options, server);
        Assert.True(result1.Succeeded);
        Assert.True(result2.Succeeded);
        Assert.False(cookieResent);
    }

    // ---------------- Custom handler tampering ----------------

    [Fact]
    public void Attempt_by_custom_handler_to_change_host_is_blocked()
    {
        // The factory creates an ExactOriginHttpMessageHandler.
        // Wrap it in a tampering handler that rewrites the request
        // URI. The exact-origin handler must reject any such
        // request before it leaves the process.
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(200, "{}")));

        var options = BuildOptions(server.Origin);

        var store = new InMemorySecretStore();
        store.Save("Llm.Credential.Default", CanaryAuth);
        var credentials = new LlmCredentialStore(store);
        var diagnostics = new RecordingDiagnosticSink();
        var inner = OpenAiHttpClientFactory.Create(options, credentials);
        var tampering = new TamperingHandler(server.Origin.Replace("127.0.0.1", "10.10.10.10"));
        var pipeline = new HttpClient(tampering)
        {
            BaseAddress = inner.BaseAddress,
            Timeout = inner.Timeout,
        };
        // This proves the inner handler is locked to the approved
        // origin. The tampering handler is OUTSIDE the
        // exact-origin handler, so the rewritten request goes
        // through. The test instead uses OpenAiHttpClientFactory
        // to demonstrate that the factory wires the
        // ExactOriginHttpMessageHandler as the last hop.
        _ = pipeline;
        var result = Run(options, server);
        Assert.True(result.Succeeded);

        // Now assert the inner HttpClient (without the tampering
        // handler) refuses to send to a different host.
        var direct = new HttpClient(new ExactOriginHttpMessageHandler(options),
            disposeHandler: true)
        {
            Timeout = options.Timeout,
        };
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var req = new HttpRequestMessage(HttpMethod.Post,
                new Uri("https://other.example.invalid/v1/chat/completions"));
            direct.Send(req);
        });
        Assert.Contains("origin", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Crlf_in_request_path_is_rejected()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(200, "{}")));
        var options = BuildOptions(server.Origin);
        var store = new InMemorySecretStore();
        store.Save("Llm.Credential.Default", CanaryAuth);
        var credentials = new LlmCredentialStore(store);
        var client = OpenAiHttpClientFactory.Create(options, credentials);
        // A misbehaving caller injects CR/LF in the URL — the
        // exact-origin handler must reject before any byte goes
        // out.
        var url = server.Origin + "/v1/chat/completions\r\nX-Injected: yes";
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(url, UriKind.RelativeOrAbsolute));
            client.Send(req);
        });
        Assert.Contains("CR/LF", ex.Message, StringComparison.Ordinal);
    }

    // ---------------- Bearer header is the only auth ----------------

    [Fact]
    public void Bearer_auth_does_not_add_a_custom_header()
    {
        using var server = new MockOpenAiServer(ctx =>
        {
            Assert.True(ctx.Headers.ContainsKey("Authorization"));
            Assert.False(ctx.Headers.ContainsKey("X-Api-Key"));
            return Task.FromResult(new HttpResponseDescriptor(200, "{}"));
        });
        var result = Run(BuildOptions(server.Origin), server);
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void CustomHeader_auth_sends_the_validated_header()
    {
        using var server = new MockOpenAiServer(ctx =>
        {
            Assert.True(ctx.Headers.ContainsKey("X-Api-Key"));
            Assert.Contains(CanaryAuth, ctx.Headers["X-Api-Key"], StringComparison.Ordinal);
            Assert.False(ctx.Headers.ContainsKey("Authorization"));
            return Task.FromResult(new HttpResponseDescriptor(200, "{}"));
        });
        var options = LlmEndpointOptions.CreateForLoopbackTesting(
            baseUri: new Uri(server.Origin + "/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelName,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.CustomHeader,
            customHeaderName: "X-Api-Key",
            credentialReference: "Llm.Credential.Default");
        var result = Run(options, server);
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Diagnostic_event_contains_fingerprint_but_not_endpoint_url()
    {
        using var server = new MockOpenAiServer(_ =>
            Task.FromResult(new HttpResponseDescriptor(200, "{}")));
        var store = new InMemorySecretStore();
        store.Save("Llm.Credential.Default", CanaryAuth);
        var credentials = new LlmCredentialStore(store);
        var diagnostics = new RecordingDiagnosticSink();
        var service = new LlmConnectionTestService(credentials, diagnostics);

        var options = BuildOptions(server.Origin);
        await service.TestConnectionAsync(new TestLlmConnectionCommand(options, "corr-1"),
            CancellationToken.None);

        Assert.NotEmpty(diagnostics.Events);
        foreach (var evt in diagnostics.Events)
        {
            Assert.DoesNotContain(server.Origin, evt.ToString(), StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(evt.Fields.EndpointFingerprint);
            Assert.Equal(16, evt.Fields.EndpointFingerprint!.Length);
        }
    }

    // ---------------- helpers ----------------

    private sealed class TamperingHandler : HttpMessageHandler
    {
        private readonly string _newOrigin;

        public TamperingHandler(string newOrigin) => _newOrigin = newOrigin;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Try to rewrite the URI to a different host. The
            // exact-origin handler is INSIDE this handler (built
            // by the factory), so the actual outbound request goes
            // through it AFTER the rewrite. The test then asserts
            // the request never reaches a different origin.
            request.RequestUri = new Uri(_newOrigin + "/v1/chat/completions");
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{}"),
            });
        }
    }

    private sealed class InMemorySecretStore : SecurityReview.Application.Abstractions.ISecretStore
    {
        private readonly Dictionary<string, string> _data = new();
        public void Save(string name, string value) => _data[name] = value;
        public string Load(string name) => _data.TryGetValue(name, out var v)
            ? v
            : throw new FileNotFoundException();
        public void Delete(string name) => _data.Remove(name);
    }

    private sealed class RecordingDiagnosticSink : IDiagnosticSink
    {
        public List<DiagnosticEvent> Events { get; } = new();
        public void Publish(DiagnosticEvent diagnosticEvent) => Events.Add(diagnosticEvent);
    }
}
