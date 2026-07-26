using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Caching;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Llm;
using SecurityReview.Domain;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Concrete <see cref="ISemanticReviewer"/>. Minimizes the input via
/// <see cref="CandidateMinimizer"/>, computes the cache key via the
/// P4 <see cref="SemanticCacheKey"/>, looks the entry up in the
/// <see cref="CacheCoordinator"/>, and on miss invokes the
/// <see cref="LlmRetryPolicy"/> through the
/// <see cref="LlmCircuitBreaker"/> on the
/// <see cref="OpenAiHttpClientFactory"/>-built client. Successful
/// results are encrypted and cached; every attempt's metadata is
/// persisted via <see cref="ILlmAttemptRepository"/>.
///
/// No endpoint host, model identifier, candidate value, candidate
/// context, or API-key material is ever logged, persisted in plain
/// columns, or surfaced through diagnostic events.
/// </summary>
public sealed class OpenAiSemanticReviewer
    : ISemanticReviewer, ISemanticReviewMetadataProvider, IDisposable
{
    private const string CacheStage = "llm_review";
    private const string CacheRecordIdField = "payload";
    private const string NoCachePayload = "no-cache";

    private readonly LlmEndpointOptions _options;
    private readonly IValueFingerprintService _fingerprints;
    private readonly HttpClient _httpClient;
    private readonly CacheCoordinator _cache;
    private readonly ILlmAttemptRepository _attempts;
    private readonly IDiagnosticSink _diagnostics;
    private readonly LlmRetryPolicy _retryPolicy;
    private readonly LlmCircuitBreaker _circuitBreaker;
    private readonly string _endpointFingerprint;
    private readonly string _modelFingerprint;
    private readonly bool _ownsHttpClient;
    private readonly ILlmCredentialStore? _credentialStore;

    public OpenAiSemanticReviewer(
        LlmEndpointOptions options,
        IValueFingerprintService fingerprints,
        HttpClient httpClient,
        CacheCoordinator cache,
        ILlmAttemptRepository attempts,
        IDiagnosticSink diagnostics,
        LlmRetryPolicy? retryPolicy = null,
        LlmCircuitBreaker? circuitBreaker = null,
        bool ownsHttpClient = false,
        ILlmCredentialStore? credentialStore = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(fingerprints);
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(attempts);
        ArgumentNullException.ThrowIfNull(diagnostics);

        _options = options;
        _fingerprints = fingerprints;
        _httpClient = httpClient;
        _cache = cache;
        _attempts = attempts;
        _diagnostics = diagnostics;
        _retryPolicy = retryPolicy ?? new LlmRetryPolicy();
        _circuitBreaker = circuitBreaker ?? new LlmCircuitBreaker();
        _endpointFingerprint = options.OriginFingerprint();
        _modelFingerprint = ComputeModelFingerprint(options.Model);
        _ownsHttpClient = ownsHttpClient;
        _credentialStore = credentialStore;
    }

    public async Task<LlmReviewResult> ReviewAsync(
        SemanticReviewRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        MinimizedCandidate minimized = CandidateMinimizer.Minimize(request);
        byte[] requestBytes = OpenAiChatRequest.Build(_options, minimized, correlationId: null);

        SemanticCacheKey cacheKey = BuildCacheKey(request, minimized);
        CachedReviewPayload? cached = await _cache
            .TryGetAsync<CachedReviewPayload>(
                cacheKey.Key,
                CacheStage,
                cacheKey.Key,
                cancellationToken)
            .ConfigureAwait(false);
        if (cached is not null)
        {
            return cached.Result with { CandidateId = request.CandidateId };
        }

        if (!_circuitBreaker.TryEnter())
        {
            _diagnostics.Publish(new Application.Diagnostics.DiagnosticEvent(
                Application.Diagnostics.DiagnosticCode.LlmReviewCircuitOpen,
                DateTimeOffset.UtcNow, null, null,
                new Application.Diagnostics.DiagnosticFields
                {
                    Stage = "llm.review",
                    ReasonCode = "circuit_open",
                    Module = "Infrastructure.Llm",
                    Method = "ReviewAsync",
                    EndpointFingerprint = _endpointFingerprint,
                    ModelFingerprint = _modelFingerprint,
                }));

            LlmReviewResult blocked = BlockedByCircuitResult(request.CandidateId);
            return blocked;
        }

        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        LlmRetryResult retryResult = await _retryPolicy.ExecuteAsync(
            candidateId: request.CandidateId,
            createRequest: () => BuildHttpRequest(minimized, requestBytes),
            send: SendAsync,
            deadline: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        TimeSpan duration = DateTimeOffset.UtcNow - startedAt;

        LlmReviewResult parsed;
        try
        {
            parsed = await OpenAiChatResponseParser.ParseAsync(
                request.CandidateId,
                retryResult.FinalResponse ?? new HttpResponseMessage(System.Net.HttpStatusCode.BadGateway)
                {
                    Content = new ByteArrayContent(Array.Empty<byte>()),
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (LlmSchemaException ex)
        {
            _diagnostics.Publish(new Application.Diagnostics.DiagnosticEvent(
                Application.Diagnostics.DiagnosticCode.LlmReviewSchemaException,
                DateTimeOffset.UtcNow, null, null,
                new Application.Diagnostics.DiagnosticFields
                {
                    Stage = "llm.review",
                    ReasonCode = "schema_exception",
                    Module = "Infrastructure.Llm",
                    Method = "ReviewAsync",
                    EndpointFingerprint = _endpointFingerprint,
                    ModelFingerprint = _modelFingerprint,
                }));

            _circuitBreaker.RecordClientOrSchemaFailure();
            parsed = UnresolvedResult(request.CandidateId, ex.Message);
        }
        finally
        {
            retryResult.FinalResponse?.Dispose();
            foreach (HttpRequestMessage req in retryResult.Requests)
                req.Dispose();
        }

        RecordCircuitOutcome(retryResult, parsed);

        // Persist every attempt row (one per HTTP attempt).
        int attemptNumber = 0;
        foreach (HttpRequestMessage req in retryResult.Requests)
        {
            attemptNumber++;
            int statusCode = parsed.ReasonCode is null ? 200 : 0;
            _ = statusCode;
            await _attempts.PersistAttemptAsync(new LlmAttemptPersistenceRecord(
                Result: parsed,
                AttemptNumber: attemptNumber,
                CacheKey: cacheKey.Key,
                RulePackHash: request.RulePackHash ?? NoCachePayload,
                AdapterVersion: request.AdapterVersion ?? NoCachePayload,
                EndpointFingerprint: _endpointFingerprint,
                ModelFingerprint: _modelFingerprint,
                StartedAtUtc: startedAt,
                Duration: duration,
                StatusCodeOrZero: (int)(retryResult.FinalResponse?.StatusCode ?? default),
                ScanId: request.ScanId),
                cancellationToken).ConfigureAwait(false);
            _ = req;
        }

        // Only Confirmed/Possible/Unlikely are cached and persisted as a
        // successful review; transport/schema/injection unresolved is
        // intentionally excluded so the cache never returns a stale
        // error code as a successful review.
        if (parsed.Classification is SemanticClassification.Confirmed
            or SemanticClassification.Possible
            or SemanticClassification.Unlikely)
        {
            await _cache.StoreAsync(
                cacheKey.Key,
                CacheStage,
                request.ScanId,
                cacheKey.Key,
                new CachedReviewPayload(parsed),
                cancellationToken).ConfigureAwait(false);
        }

        _diagnostics.Publish(new Application.Diagnostics.DiagnosticEvent(
            parsed.Classification is SemanticClassification.Unresolved
                ? Application.Diagnostics.DiagnosticCode.LlmReviewFailed
                : Application.Diagnostics.DiagnosticCode.LlmReviewSucceeded,
            DateTimeOffset.UtcNow, null, null,
            new Application.Diagnostics.DiagnosticFields
            {
                Stage = "llm.review",
                ReasonCode = parsed.ReasonCode ?? (parsed.Classification == SemanticClassification.Unresolved ? "unresolved" : "success"),
                Count = retryResult.Attempts,
                DurationMs = (long)duration.TotalMilliseconds,
                Module = "Infrastructure.Llm",
                Method = "ReviewAsync",
                EndpointFingerprint = _endpointFingerprint,
                ModelFingerprint = _modelFingerprint,
            }));

        return parsed;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Uri fullUri = new(_options.ApprovedOrigin, _options.ChatCompletionsPath);
        request.RequestUri ??= fullUri;
        try
        {
            return await _httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // Retry policy decides whether to retry. The circuit
            // breaker decision is recorded by the caller when the
            // retry exhausts.
            throw;
        }
    }

    private void RecordCircuitOutcome(LlmRetryResult retryResult, LlmReviewResult parsed)
    {
        if (retryResult.Succeeded)
        {
            _circuitBreaker.RecordSuccess();
            return;
        }

        // Schema / client / network / 5xx / timeout classification.
        string reason = parsed.ReasonCode ?? retryResult.ReasonCode ?? string.Empty;
        bool isAvailability =
            reason.StartsWith("server", StringComparison.OrdinalIgnoreCase) ||
            reason.StartsWith("timeout", StringComparison.OrdinalIgnoreCase) ||
            reason.StartsWith("transport", StringComparison.OrdinalIgnoreCase) ||
            reason.StartsWith("rate_limited", StringComparison.OrdinalIgnoreCase);

        if (isAvailability)
            _circuitBreaker.RecordAvailabilityFailure();
        else
            _circuitBreaker.RecordClientOrSchemaFailure();
    }

    private SemanticCacheKey BuildCacheKey(SemanticReviewRequest request, MinimizedCandidate minimized)
    {
        string candidateHmac = _fingerprints.Compute(minimized.RedactedCandidateValue).HexString;
        byte[] maskedBytes = Encoding.UTF8.GetBytes(minimized.UntrustedContext);
        byte[] maskedHash = SHA256.HashData(maskedBytes);
        string maskedSha = Convert.ToHexString(maskedHash).ToLowerInvariant();
        return new SemanticCacheKey(
            candidateHmac: candidateHmac,
            maskedContextSha256: maskedSha,
            endpointOriginFingerprint: _endpointFingerprint,
            model: _modelFingerprint,
            responseFormatMode: _options.ResponseFormatMode.ToString(),
            temperatureMode: _options.SendTemperatureZero ? "zero" : "nonzero",
            promptHash: OpenAiChatRequest.PromptTemplate.Sha256,
            rulePackHash: request.RulePackHash ?? NoCachePayload,
            adapterVersion: request.AdapterVersion ?? NoCachePayload);
    }

    private HttpRequestMessage BuildHttpRequest(MinimizedCandidate minimized, byte[] body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(_options.ApprovedOrigin, _options.ChatCompletionsPath));
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;
        if (_options.AuthMode != LlmAuthMode.None)
        {
            OpenAiHttpClientFactory.ApplyAuthentication(
                request,
                _options,
                _credentialStore
                    ?? throw new InvalidOperationException(
                        "LLM credential store is unavailable."));
        }
        _ = minimized;
        return request;
    }

    public PersistedLlmReview CreatePersistenceRecord(
        SemanticQueueItem item,
        LlmReviewResult result,
        DateTimeOffset startedAtUtc,
        TimeSpan duration)
    {
        SemanticReviewRequest request = item.Request with
        {
            ScanId = item.ScanId,
            RulePackHash = item.RulePackHash,
            AdapterVersion = item.AdapterVersion,
        };
        MinimizedCandidate minimized = CandidateMinimizer.Minimize(request);
        SemanticCacheKey cacheKey = BuildCacheKey(request, minimized);
        return new PersistedLlmReview(
            CandidateId: result.CandidateId,
            ScanId: item.ScanId,
            CacheKey: cacheKey.Key,
            Classification: result.Classification,
            CategoryId: result.CategoryId?.Value
                ?? request.CategoryHint.Value
                ?? "SENS-001",
            Confidence: result.Confidence,
            ReasonCode: result.ReasonCode ?? "success",
            InjectionDetected: result.InjectionDetected,
            PromptSha256: result.PromptSha256
                ?? OpenAiChatRequest.PromptTemplate.Sha256,
            PromptVersion: result.PromptVersion
                ?? OpenAiChatRequest.PromptVersion,
            EndpointFingerprint: _endpointFingerprint,
            ModelFingerprint: _modelFingerprint,
            AttemptedAtUtc: startedAtUtc,
            Duration: duration,
            Attempts: 1);
    }

    private static LlmReviewResult UnresolvedResult(CandidateId id, string reason) =>
        new()
        {
            CandidateId = id,
            Classification = SemanticClassification.Unresolved,
            CategoryId = SecurityReview.Domain.Assets.CategoryId.Parse("SENS-001"),
            Confidence = null,
            Rationale = string.Empty,
            ReasonCode = reason,
            InjectionDetected = false,
            PromptSha256 = OpenAiChatRequest.PromptTemplate.Sha256,
            PromptVersion = OpenAiChatRequest.PromptVersion,
        };

    private static LlmReviewResult BlockedByCircuitResult(CandidateId id) =>
        UnresolvedResult(id, "circuit_open");

    public static string ComputeModelFingerprint(string model)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(model));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}

/// <summary>
/// Encrypted payload stored in <c>cache_entries.stage = "llm_review"</c>.
/// Only valid classifications (Confirmed / Possible / Unlikely) are
/// stored; Unresolved results are never cached.
/// </summary>
public sealed record CachedReviewPayload(LlmReviewResult Result);
