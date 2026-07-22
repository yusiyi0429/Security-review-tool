using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Caching;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Caching;

/// <summary>
/// Verifies that every cache component change produces a cache miss.
/// Each test: store → retrieve (hit) → change one component → retrieve (miss).
/// Also verifies that tampered entries are rejected (never fail open).
/// </summary>
public sealed class CacheInvalidationMatrixTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly HkdfSha256 _hkdf;
    private readonly SqliteCacheRepository _repository;
    private readonly CacheCoordinator _coordinator;

    public CacheInvalidationMatrixTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(),
            $"cache-matrix-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _databasePath = Path.Combine(_tempDir, "cache-test.db");

        // Create the database with cache_entries table.
        using var setupConn = new SqliteConnection($"Data Source={_databasePath}");
        setupConn.Open();
        using var setupCmd = setupConn.CreateCommand();
        setupCmd.CommandText = """
            CREATE TABLE IF NOT EXISTS cache_entries (
                cache_key           TEXT PRIMARY KEY,
                stage               TEXT NOT NULL,
                created_at_utc      TEXT NOT NULL,
                last_used_at_utc    TEXT NOT NULL,
                source_scan_id      TEXT,
                encrypted_payload   BLOB
            );
            CREATE INDEX IF NOT EXISTS ix_cache_entries_stage ON cache_entries(stage);
            CREATE INDEX IF NOT EXISTS ix_cache_entries_last_used ON cache_entries(last_used_at_utc);
            """;
        setupCmd.ExecuteNonQuery();
        setupConn.Close();

        // Create crypto.
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        _hkdf = new HkdfSha256(masterKey);
        byte[] encKey = _hkdf.DeriveEncryptionKey();
        _protector = new AesGcmPayloadProtector(encKey, Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes("cache-matrix-test-key"))));

        // Create repository.
        _factory = new SqliteConnectionFactory(_databasePath);
        _repository = new SqliteCacheRepository(_factory);

        // Create coordinator with generous disk budget.
        _coordinator = new CacheCoordinator(_repository, _protector,
            new FixedDiskCapacityProvider(100L * 1024 * 1024 * 1024)); // 100 GiB free
    }

    public async ValueTask DisposeAsync()
    {
        _protector.Dispose();
        _hkdf.Dispose();
        await Task.CompletedTask;
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best-effort */ }
    }

    private sealed record TestResult(string Message);

    // ---------------------------------------------------------------
    // Matrix: parse cache key component changes
    // ---------------------------------------------------------------

    [Fact]
    public async Task ParseCache_FileSha256Change_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-aaaa-0000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser-v1", "1.0.0", "default", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-bbbb-0000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser-v1", "1.0.0", "default", "ct-v3");

        // Store using key1, retrieve should hit for key1, miss for key2.
        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("hello"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    [Fact]
    public async Task ParseCache_StreamIdentityChange_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser-v1", "1.0.0", "default", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-002", "parser-v1", "1.0.0", "default", "ct-v3");

        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("stream match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    [Fact]
    public async Task ParseCache_ParserIdChange_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "1.0.0", "default", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "pdf-v2", "1.0.0", "default", "ct-v3");

        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("parser match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    [Fact]
    public async Task ParseCache_ParserVersionChange_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.2", "default", "ct-v3");

        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("version match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    [Fact]
    public async Task ParseCache_LimitsProfileChange_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default-1mb", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "large-10mb", "ct-v3");

        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("limits match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    [Fact]
    public async Task ParseCache_ContractVersionChange_CausesMiss()
    {
        var scanId = NewScanId();
        var key1 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "ct-v3");
        var key2 = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "spreadsheet-v1", "2.0.1", "default", "ct-v4");

        await _coordinator.StoreAsync(key1.Key, "parsing", scanId,
            key1.Key, new TestResult("contract match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "parsing", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "parsing", key2.Key));
    }

    // ---------------------------------------------------------------
    // Matrix: detection cache key component changes
    // ---------------------------------------------------------------

    [Fact]
    public async Task DetectionCache_PolicySha256Change_CausesMiss()
    {
        var scanId = NewScanId();
        var parseKey = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");

        var key1 = new DetectionCacheKey(parseKey, "policy-aaa", "bundle-1.0");
        var key2 = new DetectionCacheKey(parseKey, "policy-bbb", "bundle-1.0");

        await _coordinator.StoreAsync(key1.Key, "detection", scanId,
            key1.Key, new TestResult("policy match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "detection", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "detection", key2.Key));
    }

    [Fact]
    public async Task DetectionCache_DetectorBundleVersionChange_CausesMiss()
    {
        var scanId = NewScanId();
        var parseKey = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");

        var key1 = new DetectionCacheKey(parseKey, "policy-a", "bundle-4.2.0");
        var key2 = new DetectionCacheKey(parseKey, "policy-a", "bundle-4.3.0");

        await _coordinator.StoreAsync(key1.Key, "detection", scanId,
            key1.Key, new TestResult("bundle match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "detection", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "detection", key2.Key));
    }

    [Fact]
    public async Task DetectionCache_ParseKeyChange_CausesMiss()
    {
        var scanId = NewScanId();
        var parse1 = new ParseCacheKey(
            "sha256-aaaa-0000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");
        var parse2 = new ParseCacheKey(
            "sha256-bbbb-0000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");

        var key1 = new DetectionCacheKey(parse1, "policy-a", "bundle-1.0");
        var key2 = new DetectionCacheKey(parse2, "policy-a", "bundle-1.0");

        await _coordinator.StoreAsync(key1.Key, "detection", scanId,
            key1.Key, new TestResult("detect parse match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key1.Key, "detection", key1.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key2.Key, "detection", key2.Key));
    }

    // ---------------------------------------------------------------
    // Matrix: semantic cache key component changes
    // ---------------------------------------------------------------

    private static SemanticCacheKey CreateSemanticRef() => new(
        "candidate-hmac-ref",
        "masked-context-sha256-ref",
        "endpoint-fingerprint-ref",
        "gpt-4o",
        "json_object",
        "low",
        "prompt-hash-ref",
        "rule-pack-hash-ref",
        "adapter-v1.0");

    [Fact]
    public async Task SemanticCache_CandidateHmacChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ALT",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("semantic match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_ContextSha256Change_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ALT",
            "endpoint-fingerprint-ref",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("ctx match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_EndpointChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ALT",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("ep match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_ModelChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4-turbo", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("model match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_ResponseFormatChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4o", "text", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("format match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_PromptHashChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ALT", "rule-pack-hash-ref", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("prompt match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_RulePackHashChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ALT", "adapter-v1.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("rp match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    [Fact]
    public async Task SemanticCache_AdapterVersionChange_CausesMiss()
    {
        var scanId = NewScanId();
        var refKey = CreateSemanticRef();
        var altKey = new SemanticCacheKey(
            "candidate-hmac-ref",
            "masked-context-sha256-ref",
            "endpoint-fingerprint-ref",
            "gpt-4o", "json_object", "low",
            "prompt-hash-ref", "rule-pack-hash-ref", "adapter-v2.0");

        await _coordinator.StoreAsync(refKey.Key, "llm_review", scanId,
            refKey.Key, new TestResult("adapter match"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            refKey.Key, "llm_review", refKey.Key));
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            altKey.Key, "llm_review", altKey.Key));
    }

    // ---------------------------------------------------------------
    // Tamper rejection: corrupted payload must never return a result
    // ---------------------------------------------------------------

    [Fact]
    public async Task TamperedEncryptedPayload_IsRejectedNotReturned()
    {
        var scanId = NewScanId();
        var key = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");

        // First, store a valid entry and verify retrieval works.
        await _coordinator.StoreAsync(key.Key, "parsing", scanId,
            key.Key, new TestResult("original"));
        Assert.NotNull(await _coordinator.TryGetAsync<TestResult>(
            key.Key, "parsing", key.Key));

        // Corrupt the encrypted payload in the database directly.
        await using var conn = await _factory.OpenAsync(default);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE cache_entries
            SET encrypted_payload = @tampered
            WHERE cache_key = @key;
            """;
        cmd.Parameters.AddWithValue("@key", key.Key);
        // Replace with garbage that won't decrypt.
        cmd.Parameters.AddWithValue("@tampered", (object)Encoding.UTF8.GetBytes("""
            {"Version":1,"KeyId":"fake","NonceBase64":"AAAA","CiphertextBase64":"BBBB","TagBase64":"CCCC"}
            """));
        await cmd.ExecuteNonQueryAsync(default);

        // Now retrieval must return null (fail closed).
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key.Key, "parsing", key.Key));

        // The corrupt entry should have been deleted.
        Assert.Null(await _repository.GetByKeyAsync(key.Key));
    }

    // ---------------------------------------------------------------
    // Budget eviction
    // ---------------------------------------------------------------

    [Fact]
    public async Task BudgetExhausted_SkipsCaching_NoErrorThrown()
    {
        var scanId = NewScanId();
        var tightCoordinator = new CacheCoordinator(
            _repository, _protector,
            new FixedDiskCapacityProvider(10)); // Only 10 bytes free — budget is 1 byte

        var key = new ParseCacheKey(
            "sha256-00000000000000000000000000000000000000000000000000",
            "vol-001:file-001", "parser", "1.0.0", "default", "ct-v3");

        // Should return false but not throw.
        bool stored = await tightCoordinator.StoreAsync(
            key.Key, "parsing", scanId, key.Key, new TestResult("should not store"));

        Assert.False(stored);
        Assert.Null(await _coordinator.TryGetAsync<TestResult>(
            key.Key, "parsing", key.Key));
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static ScanId NewScanId() => new(Guid.NewGuid());

    private sealed class FixedDiskCapacityProvider : IDiskCapacityProvider
    {
        private readonly long _freeBytes;
        public FixedDiskCapacityProvider(long freeBytes) => _freeBytes = freeBytes;
        public long GetFreeBytes() => _freeBytes;
    }
}
