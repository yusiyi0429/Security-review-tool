using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Llm;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Concrete <see cref="ILlmConnectionTestService"/>. Builds a locked-down
/// <see cref="HttpClient"/>, posts the literal
/// <c>SYNTHETIC_CONNECTION_TEST</c> body to the configured chat
/// completions path, and returns a
/// <see cref="LlmConnectionTestResult"/> without ever exposing the host
/// or credential to the caller. The body and the response schema are
/// fixed; no scan repository is queried.
/// </summary>
public sealed class LlmConnectionTestService : ILlmConnectionTestService
{
    private static readonly JsonSerializerOptions BodyJsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Fixed text body the connection test sends.</summary>
    public const string SyntheticBodyText = "SYNTHETIC_CONNECTION_TEST";

    /// <summary>Fixed response schema the connection test expects.</summary>
    public const string SyntheticResponseSchema = """
        {
          "type": "object",
          "properties": {
            "ok": { "type": "boolean" },
            "message": { "type": "string" }
          },
          "required": ["ok", "message"],
          "additionalProperties": false
        }
        """;

    private readonly ILlmCredentialStore _credentials;
    private readonly IDiagnosticSink _diagnostics;

    public LlmConnectionTestService(
        ILlmCredentialStore credentials,
        IDiagnosticSink diagnostics)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(diagnostics);
        _credentials = credentials;
        _diagnostics = diagnostics;
    }

    public async Task<LlmConnectionTestResult> TestConnectionAsync(
        TestLlmConnectionCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        LlmEndpointOptions options = command.Options
            ?? throw new ArgumentException(
                "Connection test requires endpoint options.", nameof(command));

        string fingerprint = options.OriginFingerprint();
        var stopwatch = Stopwatch.StartNew();

        HttpClient client = OpenAiHttpClientFactory.Create(options, _credentials);
        try
        {
            using var request = BuildRequest(options, command.CorrelationId);

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(request, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException ||
                                                    !cancellationToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                Publish(DiagnosticCode.LlmConnectionTestTimeout, fingerprint,
                    command.CorrelationId, (int)stopwatch.ElapsedMilliseconds, 0);
                return LlmConnectionTestResult.Failure(
                    LlmConnectionTestFailureReason.Timeout, null,
                    stopwatch.Elapsed, fingerprint);
            }
            catch (HttpRequestException ex)
                when (ex.InnerException is System.Security.Authentication.AuthenticationException)
            {
                stopwatch.Stop();
                Publish(DiagnosticCode.LlmConnectionTestCertificateUntrusted, fingerprint,
                    command.CorrelationId, (int)stopwatch.ElapsedMilliseconds, 0);
                return LlmConnectionTestResult.Failure(
                    LlmConnectionTestFailureReason.CertificateUntrusted, null,
                    stopwatch.Elapsed, fingerprint);
            }
            catch (InvalidOperationException ex)
            {
                stopwatch.Stop();
                var reason = MapPolicyException(ex);
                Publish(MapToCode(reason), fingerprint, command.CorrelationId,
                    (int)stopwatch.ElapsedMilliseconds, 0);
                return LlmConnectionTestResult.Failure(
                    reason, null, stopwatch.Elapsed, fingerprint);
            }

            using (response)
            {
                int status = (int)response.StatusCode;
                if (status >= 300 && status < 400)
                {
                    stopwatch.Stop();
                    Publish(DiagnosticCode.LlmConnectionTestRedirectRejected, fingerprint,
                        command.CorrelationId, (int)stopwatch.ElapsedMilliseconds, status);
                    return LlmConnectionTestResult.Failure(
                        LlmConnectionTestFailureReason.RedirectRejected, status,
                        stopwatch.Elapsed, fingerprint);
                }

                if (status is >= 200 and < 300)
                {
                    stopwatch.Stop();
                    Publish(DiagnosticCode.LlmConnectionTestSucceeded, fingerprint,
                        command.CorrelationId, (int)stopwatch.ElapsedMilliseconds, status);
                    return LlmConnectionTestResult.Success(stopwatch.Elapsed, fingerprint);
                }

                stopwatch.Stop();
                var reason = status switch
                {
                    401 or 403 => LlmConnectionTestFailureReason.AuthenticationRejected,
                    >= 500 => LlmConnectionTestFailureReason.ServerError,
                    _ => LlmConnectionTestFailureReason.RequestError,
                };
                Publish(MapToCode(reason), fingerprint, command.CorrelationId,
                    (int)stopwatch.ElapsedMilliseconds, status);
                return LlmConnectionTestResult.Failure(
                    reason, status, stopwatch.Elapsed, fingerprint);
            }
        }
        finally
        {
            client.Dispose();
        }
    }

    private static HttpRequestMessage BuildRequest(
        LlmEndpointOptions options, string? correlationId)
    {
        Uri fullUri = new(options.ApprovedOrigin, options.ChatCompletionsPath);
        var request = new HttpRequestMessage(HttpMethod.Post, fullUri);

        // Fixed body: a deterministic, synthetic request that the
        // configured endpoint must echo / accept. No scan data, no
        // prompts, no findings.
        var body = new
        {
            model = options.Model,
            messages = new[]
            {
                new { role = "user", content = SyntheticBodyText },
            },
            temperature = (int?)(options.SendTemperatureZero ? 0 : null),
            response_format = options.ResponseFormatMode switch
            {
                LlmResponseFormatMode.JsonSchema => (object)new
                {
                    type = "json_schema",
                    json_schema = new
                    {
                        name = "synthetic_connection_test",
                        schema = JsonDocument.Parse(SyntheticResponseSchema).RootElement,
                        strict = true,
                    },
                },
                LlmResponseFormatMode.JsonObject => new { type = "json_object" },
                _ => null!,
            },
        };
        string json = JsonSerializer.Serialize(body, BodyJsonOptions);
        request.Content = new StringContent(json, Encoding.UTF8, "application/json");

        if (!string.IsNullOrEmpty(correlationId))
        {
            request.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
        }

        return request;
    }

    private static LlmConnectionTestFailureReason MapPolicyException(InvalidOperationException ex)
    {
        string message = ex.Message;
        if (message.Contains("origin", StringComparison.OrdinalIgnoreCase))
            return LlmConnectionTestFailureReason.OriginMismatch;
        if (message.Contains("redirect", StringComparison.OrdinalIgnoreCase))
            return LlmConnectionTestFailureReason.RedirectRejected;
        if (message.Contains("proxy", StringComparison.OrdinalIgnoreCase))
            return LlmConnectionTestFailureReason.ProxyRejected;
        if (message.Contains("CR/LF", StringComparison.Ordinal))
            return LlmConnectionTestFailureReason.RequestError;
        return LlmConnectionTestFailureReason.RequestError;
    }

    private static DiagnosticCode MapToCode(LlmConnectionTestFailureReason reason) => reason switch
    {
        LlmConnectionTestFailureReason.Timeout => DiagnosticCode.LlmConnectionTestTimeout,
        LlmConnectionTestFailureReason.RedirectRejected => DiagnosticCode.LlmConnectionTestRedirectRejected,
        LlmConnectionTestFailureReason.CertificateUntrusted => DiagnosticCode.LlmConnectionTestCertificateUntrusted,
        LlmConnectionTestFailureReason.CertificateRevokedOffline => DiagnosticCode.LlmConnectionTestCertificateRevokedOffline,
        LlmConnectionTestFailureReason.AuthenticationRejected => DiagnosticCode.LlmConnectionTestAuthenticationRejected,
        LlmConnectionTestFailureReason.OriginMismatch => DiagnosticCode.LlmConnectionTestOriginMismatch,
        LlmConnectionTestFailureReason.ProxyRejected => DiagnosticCode.LlmConnectionTestProxyRejected,
        _ => DiagnosticCode.LlmConnectionTestFailed,
    };

    private void Publish(
        DiagnosticCode code,
        string fingerprint,
        string? correlationId,
        int durationMs,
        int statusCode)
    {
        var fields = new DiagnosticFields
        {
            Stage = "llm.connection_test",
            ReasonCode = code.ToString(),
            StatusCode = statusCode,
            DurationMs = durationMs,
            Module = "Infrastructure.Llm",
            Method = "TestConnectionAsync",
            SchemaVersion = 1,
            EndpointFingerprint = fingerprint,
        };
        var evt = new DiagnosticEvent(
            code, DateTimeOffset.UtcNow, ScanId: null, correlationId, fields);
        _diagnostics.Publish(evt);
    }
}