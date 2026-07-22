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

    // ----- Scan pipeline (P6) -----
    ScanStarted = 0x0601,
    ScanCompleted = 0x0602,
    ScanFailed = 0x0603,
    ScanCancelled = 0x0604,
    ScanPreflightPassed = 0x0605,
    ScanPreflightFailed = 0x0606,
    ScanInventoryCompleted = 0x0607,
    ScanInventoryEmpty = 0x0608,
    ScanParseDetectStarted = 0x0609,
    ScanParseDetectCompleted = 0x060A,
    ScanSemanticQueueStarted = 0x060B,
    ScanSemanticQueueCompleted = 0x060C,
    ScanReconciliationCompleted = 0x060D,

    // ----- LLM review (P6) -----
    LlmReviewSucceeded = 0x0610,
    LlmReviewFailed = 0x0611,
    LlmReviewCircuitOpen = 0x0612,
    LlmReviewSchemaException = 0x0613,
    LlmReviewCacheHit = 0x0614,
    LlmReviewCacheStored = 0x0615,

    // ----- Health checks (P6) -----
    SandboxHealthOk = 0x0620,
    SandboxHealthFailed = 0x0621,
    SandboxWorkerLaunched = 0x0622,
    SandboxWorkerFailed = 0x0623,
    DatabaseHealthOk = 0x0630,
    DatabaseHealthFailed = 0x0631,
    RulesHealthOk = 0x0640,
    RulesHealthFailed = 0x0641,
    LlmHealthOk = 0x0650,
    LlmHealthFailed = 0x0651,

    // ----- Export (P6) -----
    ExportStarted = 0x0660,
    ExportCompleted = 0x0661,
    ExportFailed = 0x0662,
    ExportRowLimitExceeded = 0x0663,
    ExportTargetExists = 0x0664,

    // ----- Diagnostic subsystem (P6) -----
    DiagnosticSinkStarted = 0x0670,
    DiagnosticBundleExported = 0x0671,
    DiagnosticBundleExportFailed = 0x0672,
    UiStartupFailed = 0x0673,
}
