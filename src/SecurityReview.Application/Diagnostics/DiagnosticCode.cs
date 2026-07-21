namespace SecurityReview.Application.Diagnostics;

/// <summary>
/// Stable diagnostic event codes. P5 emits codes from the LLM transport
/// stack; later phases add scan, review, and update codes. The set is
/// closed — each code is a distinct constant so telemetry can be
/// classified without parsing free-form messages.
/// </summary>
public enum DiagnosticCode
{
    // ----- LLM transport (P5) -----
    LlmConnectionTestSucceeded = 0x0501,
    LlmConnectionTestFailed = 0x0502,
    LlmConnectionTestRedirectRejected = 0x0503,
    LlmConnectionTestCertificateUntrusted = 0x0504,
    LlmConnectionTestCertificateRevokedOffline = 0x0505,
    LlmConnectionTestTimeout = 0x0506,
    LlmConnectionTestAuthenticationRejected = 0x0507,
    LlmConnectionTestOriginMismatch = 0x0508,
    LlmConnectionTestProxyRejected = 0x0509,
    LlmConnectionTestAmbiguousCredentialsCleared = 0x050A,
    LlmConfigurationLoaded = 0x050B,
    LlmConfigurationStored = 0x050C,
    LlmConfigurationRejected = 0x050D,
}