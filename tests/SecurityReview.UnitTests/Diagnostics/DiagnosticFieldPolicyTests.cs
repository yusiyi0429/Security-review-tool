using SecurityReview.Application.Diagnostics;
using SecurityReview.Infrastructure.Diagnostics;

namespace SecurityReview.UnitTests.Diagnostics;

public sealed class DiagnosticFieldPolicyTests
{
    [Fact]
    public void Allowlisted_fields_pass_validation()
    {
        string[] allowlisted = [
            "code", "utc", "scan_id", "stage", "reason_code", "status_code",
            "count", "duration_ms", "module", "method", "os_version",
            "app_version", "rule_version", "parser_version", "model_version",
            "prompt_version", "endpoint_fingerprint", "correlation_id",
            "schema_version", "build_version", "config_schema_version",
            "model_fingerprint", "rule_fingerprint", "parser_fingerprint",
            "prompt_fingerprint",
        ];

        foreach (string field in allowlisted)
        {
            Assert.True(DiagnosticFieldPolicy.IsFieldAllowed(field), $"Field '{field}' should be allowed.");
        }
    }

    [Fact]
    public void Blacklisted_field_names_are_rejected()
    {
        string[] blacklisted = [
            "endpoint_url", "host", "path", "file_name", "content", "value",
            "context", "body", "request", "response", "header", "token", "secret",
            "password", "cookie", "authorization", "sql", "parameter", "manifest",
            "payload", "review_reason", "stack_message",
        ];

        foreach (string field in blacklisted)
        {
            Assert.False(DiagnosticFieldPolicy.IsFieldAllowed(field), $"Field '{field}' should be rejected.");
        }
    }

    [Fact]
    public void Blacklisted_substrings_in_field_names_are_rejected()
    {
        string[] suspicious = [
            "my_url", "api_host", "file_path", "input_file_name",
            "response_body", "request_headers", "auth_token", "api_secret",
            "user_password", "session_cookie", "sql_query", "query_parameter",
            "package_manifest", "encrypted_payload",
        ];

        foreach (string field in suspicious)
        {
            Assert.False(DiagnosticFieldPolicy.IsFieldAllowed(field), $"Field '{field}' should be rejected.");
        }
    }

    [Fact]
    public void Field_values_containing_blacklisted_terms_are_rejected()
    {
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("endpoint_url", "https://secret.example.com/api"));
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("note", "Authorization: Bearer xyz"));
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("label", "password=admin123"));
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("context", "SELECT * FROM users"));
        Assert.True(DiagnosticFieldPolicy.IsFieldValueSafe("stage", "llm.connection_test"));
        Assert.True(DiagnosticFieldPolicy.IsFieldValueSafe("reason_code", "timeout"));
        Assert.True(DiagnosticFieldPolicy.IsFieldValueSafe("module", "Infrastructure.Llm"));
    }

    [Fact]
    public void Numeric_fields_within_range_are_allowed()
    {
        Assert.True(DiagnosticFieldPolicy.IsFieldAllowed("count"));
        Assert.True(DiagnosticFieldPolicy.IsFieldAllowed("duration_ms"));
        Assert.True(DiagnosticFieldPolicy.IsFieldAllowed("status_code"));
        Assert.True(DiagnosticFieldPolicy.IsFieldAllowed("retry_after_seconds"));
    }

    [Fact]
    public void Sanitized_diagnostic_fields_produce_valid_event()
    {
        var fields = new DiagnosticFields
        {
            Stage = "scan.pipeline",
            ReasonCode = "completed",
            StatusCode = 200,
            Count = 42,
            DurationMs = 1500,
            Module = "Application.Scans",
            Method = "RunPipelineAsync",
            SchemaVersion = 1,
            BuildVersion = "2.0.0",
            OSVersion = "Windows 11.0.26100",
            EndpointFingerprint = "a1b2c3d4e5f6a7b8",
            ModelFingerprint = "b2c3d4e5f6a7b8c9",
        };

        var evt = new DiagnosticEvent(
            DiagnosticCode.ScanStarted,
            DateTimeOffset.UtcNow,
            new Domain.ScanId(Guid.NewGuid()),
            "corr-001",
            fields);

        Assert.True(DiagnosticFieldPolicy.ValidateEvent(evt).IsValid);
    }

    [Fact]
    public void Event_code_must_be_defined()
    {
        var evt = new DiagnosticEvent(
            (DiagnosticCode)0xFFFF,
            DateTimeOffset.UtcNow,
            null, null,
            new DiagnosticFields());

        var result = DiagnosticFieldPolicy.ValidateEvent(evt);
        Assert.False(result.IsValid);
        Assert.Contains("code", result.Violations[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Worker_payload_tostring_is_never_logged()
    {
        // Simulating a field that would contain a ToString of a worker payload
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("payload", "WorkerPayload { Body: ... }"));
        Assert.False(DiagnosticFieldPolicy.IsFieldValueSafe("data", "WorkerPayload { ... }"));
    }
}
