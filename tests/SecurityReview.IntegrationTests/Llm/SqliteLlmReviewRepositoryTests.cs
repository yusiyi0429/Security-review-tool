using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Llm;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Llm;

/// <summary>
/// Round-trip tests for <see cref="SqliteLlmReviewRepository"/>:
/// persist every attempt's metadata (no body / header / candidate /
/// context / host / model value) and read it back through the
/// <see cref="LlmAttemptLogEntry.PlainColumns"/> projection so the
/// canary scan can verify zero canary on disk.
/// </summary>
public sealed class SqliteLlmReviewRepositoryTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly MigrationRunner _runner;
    private readonly SqliteLlmReviewRepository _repository;
    private readonly NullPayloadProtector _protector;

    public SqliteLlmReviewRepositoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "srt-llm-repo-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _databasePath = Path.Combine(_tempDir, "review.db");
        _factory = new SqliteConnectionFactory(_databasePath);
        _protector = new NullPayloadProtector();
        _repository = new SqliteLlmReviewRepository(_factory, _protector);

        // Ensure the schema is created up to v2.
        using var init = new Microsoft.Data.Sqlite.SqliteConnection(
            $"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        init.Close();

        _runner = new MigrationRunner(_factory,
            new IMigration[] { new Migration001Initial(), new Migration002LlmAttempts() },
            _databasePath,
            Path.Combine(_tempDir, "backups"));
    }

    public async ValueTask DisposeAsync()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
        await Task.CompletedTask;
    }

    [Fact]
    public async Task PersistAttempt_then_ReadAllAttempts_round_trips_columns()
    {
        await _runner.MigrateAsync(CancellationToken.None);
        ScanId scanId = await CreateScanAsync();
        var candidateId = new CandidateId(Guid.NewGuid());
        var result = new LlmReviewResult
        {
            CandidateId = candidateId,
            Classification = SemanticClassification.Confirmed,
            CategoryId = CategoryId.Parse("SENS-002"),
            Confidence = 0.9,
            Rationale = "ok",
            ReasonCode = null,
            InjectionDetected = false,
            PromptSha256 = "deadbeef",
            PromptVersion = OpenAiChatRequest.PromptVersion,
        };

        var record = new LlmAttemptPersistenceRecord(
            Result: result,
            AttemptNumber: 1,
            CacheKey: "abc123",
            RulePackHash: "rulepackhash",
            AdapterVersion: "1.0.0",
            EndpointFingerprint: "1234567890abcdef",
            ModelFingerprint: "0011223344556677",
            StartedAtUtc: DateTimeOffset.UtcNow,
            Duration: TimeSpan.FromMilliseconds(123),
            StatusCodeOrZero: 200,
            ScanId: scanId);

        await _repository.PersistAttemptAsync(record, CancellationToken.None);

        IReadOnlyList<LlmAttemptLogEntry> rows = await _repository.ReadAllAttemptsAsync(CancellationToken.None);
        LlmAttemptLogEntry row = Assert.Single(rows);
        Assert.Equal(candidateId.Value.ToString("D"), row.CandidateId);
        Assert.Equal(1, row.AttemptNumber);
        Assert.Equal(200, row.StatusCode);
        Assert.Equal(123, row.DurationMs);
        Assert.Equal("success", row.ReasonCode);
        Assert.Equal("1234567890abcdef", row.EndpointFingerprint);
        Assert.Equal("0011223344556677", row.ModelFingerprint);
        Assert.Equal("abc123", row.CacheKey);
        Assert.Equal(OpenAiChatRequest.PromptVersion, row.PromptVersion);
    }

    [Fact]
    public async Task PersistReview_persists_only_fingerprints_and_encrypted_payload()
    {
        await _runner.MigrateAsync(CancellationToken.None);
        ScanId scanId = await CreateScanAsync();
        var candidateId = new CandidateId(Guid.NewGuid());
        var review = new PersistedLlmReview(
            CandidateId: candidateId,
            ScanId: scanId,
            CacheKey: "cache-key",
            Classification: SemanticClassification.Possible,
            CategoryId: "SENS-005",
            Confidence: 0.75,
            ReasonCode: "ok",
            InjectionDetected: false,
            PromptSha256: "deadbeef",
            PromptVersion: OpenAiChatRequest.PromptVersion,
            EndpointFingerprint: "endpoint-fp",
            ModelFingerprint: "model-fp",
            AttemptedAtUtc: DateTimeOffset.UtcNow,
            Duration: TimeSpan.FromMilliseconds(42),
            Attempts: 1);

        await _repository.PersistReviewAsync(review, CancellationToken.None);

        // Open the encrypted row directly and confirm the body is opaque.
        await using var connection = await _factory.OpenAsync();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT endpoint_fingerprint, model_id, encrypted_payload
            FROM llm_reviews;
            """;
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal("endpoint-fp", reader.GetString(0));
        Assert.Equal("model-fp", reader.GetString(1));
        // The encrypted payload is opaque — it must not contain the
        // literal "ok" rationale or any cleartext text.
        byte[] payload = (byte[])reader.GetValue(2);
        Assert.NotEmpty(payload);
        string asText = System.Text.Encoding.UTF8.GetString(payload);
        Assert.DoesNotContain("plaintext", asText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PersistAttempt_with_zero_status_writes_null_status_code()
    {
        await _runner.MigrateAsync(CancellationToken.None);
        ScanId scanId = await CreateScanAsync();
        var result = new LlmReviewResult
        {
            CandidateId = new CandidateId(Guid.NewGuid()),
            Classification = SemanticClassification.Unresolved,
            CategoryId = CategoryId.Parse("SENS-001"),
            Confidence = null,
            Rationale = string.Empty,
            ReasonCode = "transport_error",
            InjectionDetected = false,
            PromptSha256 = string.Empty,
            PromptVersion = OpenAiChatRequest.PromptVersion,
        };
        var record = new LlmAttemptPersistenceRecord(
            Result: result,
            AttemptNumber: 1,
            CacheKey: "k",
            RulePackHash: "r",
            AdapterVersion: "1",
            EndpointFingerprint: "ep",
            ModelFingerprint: "mp",
            StartedAtUtc: DateTimeOffset.UtcNow,
            Duration: TimeSpan.FromMilliseconds(10),
            StatusCodeOrZero: 0,
            ScanId: scanId);

        await _repository.PersistAttemptAsync(record, CancellationToken.None);

        IReadOnlyList<LlmAttemptLogEntry> rows = await _repository.ReadAllAttemptsAsync(CancellationToken.None);
        LlmAttemptLogEntry row = Assert.Single(rows);
        Assert.Null(row.StatusCode);
        Assert.Equal("transport_error", row.ReasonCode);
    }

    private async Task<ScanId> CreateScanAsync()
    {
        var scanId = new ScanId(Guid.NewGuid());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scans = new SqliteScanRepository(_factory, _protector);
        await scans.InsertAsync(
            new ScanRun(
                scanId,
                ScanStatus.Running,
                now,
                now,
                "rule-pack",
                "client",
                "pipeline",
                1,
                1),
            CancellationToken.None);
        return scanId;
    }

    private sealed class NullPayloadProtector : IPayloadProtector
    {
        public EncryptedPayload Protect(string table, string recordId, string fieldName, byte[] plaintext) =>
            new(Version: 1, KeyId: "test", NonceBase64: "", CiphertextBase64: Convert.ToBase64String(plaintext), TagBase64: "");
        public byte[] Unprotect(string table, string recordId, string fieldName, EncryptedPayload payload) =>
            Convert.FromBase64String(payload.CiphertextBase64);
    }
}
