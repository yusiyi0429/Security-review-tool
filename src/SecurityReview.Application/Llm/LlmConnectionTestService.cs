using SecurityReview.Application.Diagnostics;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Outcome of a benign LLM connection test. Every field is either a
/// status flag, an integer count, or a non-PII fingerprint. The host,
/// URL, request body, and credential value are never carried back to
/// callers — diagnostic logs only see the
/// <see cref="DiagnosticEvent.Code"/> and the
/// <see cref="DiagnosticFields.EndpointFingerprint"/>.
/// </summary>
public sealed record LlmConnectionTestResult(
    bool Succeeded,
    LlmConnectionTestFailureReason FailureReason,
    int? HttpStatusCode,
    TimeSpan Duration,
    string EndpointFingerprint)
{
    public static LlmConnectionTestResult Success(TimeSpan duration, string fingerprint) =>
        new(true, LlmConnectionTestFailureReason.None, 200, duration, fingerprint);

    public static LlmConnectionTestResult Failure(
        LlmConnectionTestFailureReason reason,
        int? statusCode,
        TimeSpan duration,
        string fingerprint) =>
        new(false, reason, statusCode, duration, fingerprint);
}

/// <summary>
/// Closed set of failure reasons emitted by the LLM connection test.
/// Each value maps to a stable <see cref="DiagnosticCode"/> so telemetry
/// and audit logs can be correlated without reading free-form text.
/// </summary>
public enum LlmConnectionTestFailureReason
{
    None = 0,
    Timeout = 1,
    RedirectRejected = 2,
    CertificateUntrusted = 3,
    CertificateRevokedOffline = 4,
    AuthenticationRejected = 5,
    OriginMismatch = 6,
    ProxyRejected = 7,
    ServerError = 8,
    RequestError = 9,
}

/// <summary>
/// Application-layer contract for running the benign LLM connection
/// test. The service is composed with the exact-origin HTTP handler
/// (Step 4) and the DPAPI credential store (Step 5) so callers receive
/// a pre-validated <see cref="LlmConnectionTestResult"/> without
/// touching credential buffers directly.
/// </summary>
public interface ILlmConnectionTestService
{
    Task<LlmConnectionTestResult> TestConnectionAsync(
        TestLlmConnectionCommand command,
        CancellationToken cancellationToken = default);
}
