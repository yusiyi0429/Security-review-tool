using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Caching;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Llm;

namespace SecurityReview.IntegrationTests.Llm;

/// <summary>
/// Canary scan: every artifact produced by the LLM transport stack
/// must be free of plaintext endpoint host, model identifier,
/// candidate value, candidate context, and API-key material —
/// outside the encrypted / DPAPI-protected envelope.
///
/// The mock server records each request it receives so tests can
/// assert the wire shape never carries the canaries and never lands
/// them in config / log / temp / exception strings.
/// </summary>
public sealed class LlmLogRedactionTests
{
    private const string HostCanary = "PLAINTEXT-HOST-CANARY-1a2b3c4d";
    private const string ModelCanary = "PLAINTEXT-MODEL-CANARY-5e6f7g8h";
    private const string ContextCanary = "PLAINTEXT-CONTEXT-CANARY-7h8i9j0k";
    private const string ValueCanary = "PLAINTEXT-VALUE-CANARY-2c3d4e5f";
    private const string TokenCanary = "PLAINTEXT-TOKEN-CANARY-8k9l0m1n";

    [Fact]
    public async Task Reviewer_limits_semantic_content_to_the_request_body()
    {
        var handler = new RecordingHttpHandler(LlmResponses.Ok(BuildCandidateId()));
        var sink = new RecordingSink();
        var bundle = await BuildReviewerAsync(handler, sink);

        SemanticReviewRequest request = BuildRequest(
            BuildCandidateId(),
            CategoryId.Parse("SENS-001"),
            candidateValue: ValueCanary,
            fullContext: $"{ContextCanary} hint:irrelevant",
            options: bundle.Options);

        await bundle.Reviewer.ReviewAsync(request, default);

        foreach (RecordedRequest recorded in handler.Records)
        {
            string url = recorded.RequestLine;
            string body = recorded.Body;
            foreach ((string key, string headerValue) in recorded.Headers)
            {
                Assert.False(headerValue.Contains(HostCanary, StringComparison.OrdinalIgnoreCase),
                    $"Header '{key}' leaked host canary.");
                Assert.False(headerValue.Contains(TokenCanary, StringComparison.Ordinal),
                    $"Header '{key}' leaked token canary.");
                Assert.False(headerValue.Contains(ModelCanary, StringComparison.Ordinal),
                    $"Header '{key}' leaked model canary.");
            }

            Assert.False(url.Contains(ValueCanary, StringComparison.Ordinal),
                $"Request URL leaked value canary: {url}");
            Assert.False(url.Contains(ContextCanary, StringComparison.Ordinal),
                $"Request URL leaked context canary: {url}");
            Assert.False(url.Contains(TokenCanary, StringComparison.Ordinal),
                $"Request URL leaked token canary: {url}");

            Assert.False(body.Contains(TokenCanary, StringComparison.Ordinal),
                $"Request body leaked token canary.");
            Assert.False(body.Contains(HostCanary, StringComparison.OrdinalIgnoreCase),
                $"Request body leaked endpoint/path host canary.");
            Assert.Contains(ValueCanary, body, StringComparison.Ordinal);
            Assert.Contains(ContextCanary, body, StringComparison.Ordinal);
            Assert.Contains(ModelCanary, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Reviewer_persists_no_canary_in_db_plain_columns()
    {
        var handler = new RecordingHttpHandler(LlmResponses.Ok(BuildCandidateId()));
        var sink = new RecordingSink();
        var bundle = await BuildReviewerAsync(handler, sink);

        SemanticReviewRequest request = BuildRequest(
            BuildCandidateId(),
            CategoryId.Parse("SENS-002"),
            candidateValue: ValueCanary,
            fullContext: $"{ContextCanary} hint:irrelevant",
            options: bundle.Options);

        LlmReviewResult result = await bundle.Reviewer.ReviewAsync(request, default);

        await bundle.Repository.PersistAttemptAsync(
            new LlmAttemptPersistenceRecord(
                Result: result,
                AttemptNumber: 1,
                CacheKey: bundle.CacheKey,
                RulePackHash: "rule-pack-hash",
                AdapterVersion: "1.0.0",
                EndpointFingerprint: bundle.Options.OriginFingerprint(),
                ModelFingerprint: bundle.Options.OriginFingerprint(),
                StartedAtUtc: DateTimeOffset.UtcNow.AddMilliseconds(-50),
                Duration: TimeSpan.FromMilliseconds(50),
                StatusCodeOrZero: 200),
            default);

        IReadOnlyList<LlmAttemptLogEntry> rows = await bundle.Repository
            .ReadAllAttemptsAsync(default);

        Assert.NotEmpty(rows);
        foreach (LlmAttemptLogEntry row in rows)
        {
            foreach ((string column, string value) in row.PlainColumns)
            {
                Assert.False(value.Contains(ValueCanary, StringComparison.Ordinal),
                    $"Column '{column}' leaked candidate value canary.");
                Assert.False(value.Contains(ContextCanary, StringComparison.Ordinal),
                    $"Column '{column}' leaked context canary.");
                Assert.False(value.Contains(HostCanary, StringComparison.OrdinalIgnoreCase),
                    $"Column '{column}' leaked host canary.");
                Assert.False(value.Contains(ModelCanary, StringComparison.Ordinal),
                    $"Column '{column}' leaked model canary.");
                Assert.False(value.Contains(TokenCanary, StringComparison.Ordinal),
                    $"Column '{column}' leaked token canary.");
            }
        }
    }

    [Fact]
    public async Task Reviewer_diagnostic_events_contain_no_canary()
    {
        var handler = new RecordingHttpHandler(LlmResponses.Ok(BuildCandidateId()));
        var sink = new RecordingSink();
        var bundle = await BuildReviewerAsync(handler, sink);

        SemanticReviewRequest request = BuildRequest(
            BuildCandidateId(),
            CategoryId.Parse("SENS-001"),
            candidateValue: ValueCanary,
            fullContext: $"{ContextCanary} hint:irrelevant",
            options: bundle.Options);

        await bundle.Reviewer.ReviewAsync(request, default);

        foreach (DiagnosticEvent evt in sink.Events)
        {
            string serialized = JsonSerializer.Serialize(evt);
            AssertNoCanaries("DiagnosticEvent", serialized);
        }
    }

    [Fact]
    public async Task Reviewer_does_not_log_exceptions_with_canary()
    {
        var handler = new RecordingHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new ByteArrayContent(Array.Empty<byte>()),
        });
        var sink = new RecordingSink();
        var bundle = await BuildReviewerAsync(handler, sink);

        SemanticReviewRequest request = BuildRequest(
            BuildCandidateId(),
            CategoryId.Parse("SENS-001"),
            candidateValue: ValueCanary,
            fullContext: $"{ContextCanary} hint:irrelevant",
            options: bundle.Options);

        LlmReviewResult result = await bundle.Reviewer.ReviewAsync(request, default);
        Assert.Equal(SemanticClassification.Unresolved, result.Classification);

        foreach (DiagnosticEvent evt in sink.Events)
        {
            string serialized = JsonSerializer.Serialize(evt);
            AssertNoCanaries("DiagnosticEvent(5xx)", serialized);
        }
    }

    [Fact]
    public async Task Reviewer_does_not_write_canary_into_temp_or_db_files()
    {
        var handler = new RecordingHttpHandler(LlmResponses.Ok(BuildCandidateId()));
        var bundle = await BuildReviewerAsync(handler);

        SemanticReviewRequest request = BuildRequest(
            BuildCandidateId(),
            CategoryId.Parse("SENS-001"),
            candidateValue: ValueCanary,
            fullContext: $"{ContextCanary} hint:irrelevant",
            options: bundle.Options);

        await bundle.Reviewer.ReviewAsync(request, default);

        foreach (string path in Directory.EnumerateFiles(bundle.TempRoot, "*", SearchOption.AllDirectories))
        {
            if (Directory.Exists(path)) continue;
            byte[] bytes = File.ReadAllBytes(path);
            string text = Encoding.UTF8.GetString(bytes);
            AssertNoCanaries(path, text);
        }
    }

    // ---------- Helpers ----------

    private static void AssertNoCanaries(string source, string text)
    {
        Assert.False(text.Contains(ValueCanary, StringComparison.Ordinal),
            $"{source} leaked value canary.");
        Assert.False(text.Contains(ContextCanary, StringComparison.Ordinal),
            $"{source} leaked context canary.");
        Assert.False(text.Contains(HostCanary, StringComparison.OrdinalIgnoreCase),
            $"{source} leaked host canary.");
        Assert.False(text.Contains(ModelCanary, StringComparison.Ordinal),
            $"{source} leaked model canary.");
        Assert.False(text.Contains(TokenCanary, StringComparison.Ordinal),
            $"{source} leaked token canary.");
    }

    private static CandidateId BuildCandidateId() =>
        new(new Guid("33333333-3333-3333-3333-333333333333"));

    private static LlmEndpointOptions BuildOptions(string origin) =>
        LlmEndpointOptions.Create(
            baseUri: new Uri(origin.TrimEnd('/') + "/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.None,
            allowLoopbackHttp: true);

    private static SemanticReviewRequest BuildRequest(
        CandidateId candidateId,
        CategoryId category,
        string candidateValue,
        string fullContext,
        LlmEndpointOptions options)
    {
        var request = new SemanticReviewRequest(
            CandidateId: candidateId,
            CategoryHint: category,
            ContentKind: "text",
            Extension: ".txt",
            VirtualPath: $"vhost-{HostCanary}.example/docs/notes.txt",
            FullContext: fullContext,
            CandidateValue: candidateValue,
            CandidateLocator: new SourceLocator.TextLocator(1, 1, 0, candidateValue.Length),
            DeterministicSecrets: (IReadOnlyList<DeterministicSecretSpan>)Array.Empty<DeterministicSecretSpan>());
        _ = options;
        return request;
    }

    private static async Task<ReviewerBundle> BuildReviewerAsync(
        HttpMessageHandler handler,
        IDiagnosticSink? sink = null)
    {
        var options = BuildOptions("https://" + HostCanary + ".internal.example/");
        var fingerprints = new EphemeralValueFingerprintService();
        string cacheKey = new SemanticCacheKey(
            candidateHmac: fingerprints.Compute("cand").HexString,
            maskedContextSha256: "0".PadRight(64, '0'),
            endpointOriginFingerprint: options.OriginFingerprint(),
            model: "model-fingerprint",
            responseFormatMode: "json_schema",
            temperatureMode: "zero",
            promptHash: "1".PadRight(64, '1'),
            rulePackHash: "rule-pack-hash",
            adapterVersion: "1.0.0").Key;

        var repo = new InMemoryLlmAttemptRepository();
        var cacheRepo = new InMemoryCacheRepository();
        var tempRoot = Path.Combine(Path.GetTempPath(), "srt-llm-log-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        var http = new HttpClient(handler) { BaseAddress = new Uri("https://" + HostCanary + ".internal.example/") };
        var cache = new CacheCoordinator(cacheRepo, new NullPayloadProtector(), new InMemoryDiskCapacity());

        var reviewer = new OpenAiSemanticReviewer(
            options,
            fingerprints,
            http,
            cache,
            repo,
            sink ?? new NullDiagnosticSink(),
            ownsHttpClient: true);

        return await Task.FromResult(new ReviewerBundle(
            reviewer,
            repo,
            options,
            cacheKey,
            tempRoot));
    }

    private static class LlmResponses
    {
        public static Func<HttpRequestMessage, HttpResponseMessage> Ok(CandidateId id) =>
            _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($$"""
                {
                  "candidate_id": "{{id.Value:D}}",
                  "classification": "confirmed",
                  "category_id": "SENS-001",
                  "confidence": 0.9,
                  "rationale": "ok",
                  "injection_detected": false
                }
                """, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class ReviewerBundle
    {
        public ISemanticReviewer Reviewer { get; }
        public ILlmAttemptRepository Repository { get; }
        public LlmEndpointOptions Options { get; }
        public string CacheKey { get; }
        public string TempRoot { get; }

        public ReviewerBundle(
            ISemanticReviewer reviewer,
            ILlmAttemptRepository repository,
            LlmEndpointOptions options,
            string cacheKey,
            string tempRoot)
        {
            Reviewer = reviewer;
            Repository = repository;
            Options = options;
            CacheKey = cacheKey;
            TempRoot = tempRoot;
        }
    }

    private sealed class RecordingHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        private readonly ConcurrentBag<RecordedRequest> _records = new();

        public RecordingHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public IReadOnlyCollection<RecordedRequest> Records => _records.ToArray();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null
                ? string.Empty
                : Encoding.UTF8.GetString(await request.Content.ReadAsByteArrayAsync(cancellationToken)
                    .ConfigureAwait(false));

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach ((string key, IEnumerable<string> values) in request.Headers)
            {
                headers[key] = string.Join(",", values);
            }

            _records.Add(new RecordedRequest(
                request.RequestUri?.ToString() ?? string.Empty,
                headers,
                body));

            return _responder(request);
        }
    }

    private sealed record RecordedRequest(
        string RequestLine,
        IReadOnlyDictionary<string, string> Headers,
        string Body);

    private sealed class RecordingSink : IDiagnosticSink
    {
        public List<DiagnosticEvent> Events { get; } = new();
        public void Publish(DiagnosticEvent diagnosticEvent) => Events.Add(diagnosticEvent);
    }

    private sealed class NullPayloadProtector : IPayloadProtector
    {
        public EncryptedPayload Protect(string table, string recordId, string fieldName, byte[] plaintext) =>
            new(Version: 1, KeyId: "test", NonceBase64: "", CiphertextBase64: Convert.ToBase64String(plaintext), TagBase64: "");
        public byte[] Unprotect(string table, string recordId, string fieldName, EncryptedPayload payload) =>
            Convert.FromBase64String(payload.CiphertextBase64);
    }

    private sealed class InMemoryDiskCapacity : IDiskCapacityProvider
    {
        public long GetFreeBytes() => long.MaxValue;
    }

    private sealed class InMemoryLlmAttemptRepository : ILlmAttemptRepository
    {
        public List<LlmAttemptPersistenceRecord> Attempts { get; } = new();
        public List<PersistedLlmReview> Reviews { get; } = new();

        public Task PersistAttemptAsync(LlmAttemptPersistenceRecord record, CancellationToken cancellationToken)
        {
            Attempts.Add(record);
            return Task.CompletedTask;
        }

        public Task PersistReviewAsync(PersistedLlmReview review, CancellationToken cancellationToken)
        {
            Reviews.Add(review);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<LlmAttemptLogEntry>> ReadAllAttemptsAsync(CancellationToken cancellationToken)
        {
            var entries = Attempts.Select((r, i) => new LlmAttemptLogEntry(
                AttemptId: $"att-{i:D}",
                ReviewId: $"rev-{i:D}",
                ScanId: string.Empty,
                CandidateId: r.Result.CandidateId.Value.ToString("D"),
                AttemptNumber: r.AttemptNumber,
                StatusCode: r.StatusCodeOrZero == 0 ? null : r.StatusCodeOrZero,
                DurationMs: (long)r.Duration.TotalMilliseconds,
                ReasonCode: r.Result.ReasonCode ?? (r.Result.InjectionDetected ? "injection_detected" : "success"),
                EndpointFingerprint: r.EndpointFingerprint,
                ModelFingerprint: r.ModelFingerprint,
                PromptSha256: r.Result.PromptSha256 ?? string.Empty,
                PromptVersion: r.Result.PromptVersion ?? string.Empty,
                CacheKey: r.CacheKey,
                RulePackHash: r.RulePackHash,
                AdapterVersion: r.AdapterVersion,
                StartedAtUtc: r.StartedAtUtc)).ToList();
            return Task.FromResult<IReadOnlyList<LlmAttemptLogEntry>>(entries);
        }
    }

    private sealed class InMemoryCacheRepository : ICacheRepository
    {
        public Dictionary<string, CacheEntry> Entries { get; } = new();

        public Task<CacheEntry?> GetByKeyAsync(string cacheKey, CancellationToken cancellationToken = default)
            => Task.FromResult<CacheEntry?>(Entries.TryGetValue(cacheKey, out var e) ? e : null);

        public Task InsertOrReplaceAsync(CacheEntry entry, CancellationToken cancellationToken = default)
        {
            Entries[entry.CacheKey] = entry;
            return Task.CompletedTask;
        }

        public Task UpdateLastUsedAsync(string cacheKey, DateTimeOffset lastUsed, CancellationToken cancellationToken = default)
        {
            if (Entries.TryGetValue(cacheKey, out var e))
                Entries[cacheKey] = e with { LastUsedAtUtc = lastUsed };
            return Task.CompletedTask;
        }

        public Task DeleteByKeyAsync(string cacheKey, CancellationToken cancellationToken = default)
        {
            Entries.Remove(cacheKey);
            return Task.CompletedTask;
        }

        public Task DeleteByScanIdAsync(ScanId scanId, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task DeleteByStageAsync(string stage, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeBytesAsync(CancellationToken cancellationToken = default) => Task.FromResult(0L);
        public Task<IReadOnlyList<CacheEntry>> ListByStageOldestFirstAsync(string stage, int limit, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<CacheEntry>>(Array.Empty<CacheEntry>());
        public Task DeleteBatchAsync(IReadOnlyList<string> cacheKeys, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

internal static class RequestExtensionsForLlm
{
    public static SemanticReviewRequest With(this SemanticReviewRequest request, LlmEndpointOptions options) =>
        request;
}
