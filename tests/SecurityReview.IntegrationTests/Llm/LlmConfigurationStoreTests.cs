using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Llm;
using SecurityReview.Infrastructure.Persistence;

namespace SecurityReview.IntegrationTests.Llm;

/// <summary>
/// Integration tests for the JSON-backed LLM configuration store. The
/// tests confirm: (1) the on-disk reference document is the minimal
/// privacy-preserving projection (no host, model, header, or
/// credential text), (2) the underlying payload is DPAPI-protected
/// under the same Windows user, (3) tampering with the DPAPI
/// ciphertext is rejected on load, and (4) no plaintext canary for
/// host/model/header/token is found anywhere in the config /
/// diagnostic / temp directories.
/// </summary>
public sealed class LlmConfigurationStoreTests : IAsyncDisposable
{
    private const string HostCanary = "PLAINTEXT-HOST-CANARY-1a2b3c4d";
    private const string ModelCanary = "PLAINTEXT-MODEL-CANARY-5e6f7g8h";
    private const string HeaderCanary = "PLAINTEXT-HEADER-CANARY-9i0j1k2l";
    private const string TokenCanary = "PLAINTEXT-TOKEN-CANARY-3m4n5o6p";

    private readonly string _tempRoot;
    private readonly AppDataPaths _paths;
    private readonly WindowsDpapiSecretStore _secretStore;
    private readonly EphemeralValueFingerprintService _fingerprints;
    private readonly JsonLlmConfigurationStore _store;

    public LlmConfigurationStoreTests()
    {
        _tempRoot = Directory.CreateTempSubdirectory("srt-llm-cfg-").FullName;
        _paths = AppDataPaths.CreateForTest(_tempRoot);
        _paths.EnsureCreated();
        _secretStore = new WindowsDpapiSecretStore(Path.Combine(_paths.Config, "secrets"));
        _fingerprints = new EphemeralValueFingerprintService();
        _store = new JsonLlmConfigurationStore(_paths, _secretStore, _fingerprints);
    }

    public async ValueTask DisposeAsync()
    {
        _fingerprints.Dispose();
        try { Directory.Delete(_tempRoot, recursive: true); } catch { /* best effort */ }
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Save_and_load_round_trip_under_same_windows_user()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/llm/"),
            chatCompletionsPath: "/llm/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default",
            customHeaderName: HeaderCanary,
            timeout: TimeSpan.FromSeconds(45),
            maxConcurrency: 3);
        _secretStore.Save("Llm.Credential.Default", TokenCanary);

        LlmConfigurationReference reference = await _store.SaveAsync(options);
        LlmEndpointOptions? loaded = await _store.LoadAsync();

        Assert.NotNull(loaded);
        Assert.Equal(options.BaseUri, loaded!.BaseUri);
        Assert.Equal(options.Model, loaded.Model);
        Assert.Equal(options.AuthMode, loaded.AuthMode);
        Assert.Equal(options.CustomHeaderName, loaded.CustomHeaderName);
        Assert.Equal(options.MaxConcurrency, loaded.MaxConcurrency);
        Assert.Equal(JsonLlmConfigurationStore.SchemaVersion, reference.SchemaVersion);
        Assert.Equal(16, reference.EndpointFingerprint.Length);
    }

    [Fact]
    public async Task Reference_document_contains_no_plaintext_canary()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default",
            customHeaderName: HeaderCanary);
        _secretStore.Save("Llm.Credential.Default", TokenCanary);

        await _store.SaveAsync(options);

        string referenceText = await File.ReadAllTextAsync(_store.ReferenceFilePath);
        Assert.DoesNotContain(HostCanary, referenceText, StringComparison.Ordinal);
        Assert.DoesNotContain(ModelCanary, referenceText, StringComparison.Ordinal);
        Assert.DoesNotContain(HeaderCanary, referenceText, StringComparison.Ordinal);
        Assert.DoesNotContain(TokenCanary, referenceText, StringComparison.Ordinal);

        // Verify the schema fields we expect to find in the
        // reference document. The fields are PascalCase by
        // default; assert against the canonical property names.
        Assert.Contains("SchemaVersion", referenceText, StringComparison.Ordinal);
        Assert.Contains("ConfigReference", referenceText, StringComparison.Ordinal);
        Assert.Contains("EndpointFingerprint", referenceText, StringComparison.Ordinal);
        Assert.Contains("UpdatedAtUtc", referenceText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Secret_store_directory_contains_no_plaintext_canary()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default",
            customHeaderName: HeaderCanary);
        _secretStore.Save("Llm.Credential.Default", TokenCanary);

        await _store.SaveAsync(options);

        // Every file under {Config}/secrets must be DPAPI ciphertext
        // (or a directory entry), never plaintext.
        string secretsDir = Path.Combine(_paths.Config, "secrets");
        foreach (string file in Directory.EnumerateFiles(secretsDir, "*", SearchOption.AllDirectories))
        {
            byte[] bytes = await File.ReadAllBytesAsync(file);
            string text = Encoding.UTF8.GetString(bytes);
            Assert.DoesNotContain(HostCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(ModelCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(HeaderCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(TokenCanary, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Tampered_dpapi_payload_is_rejected()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default");
        _secretStore.Save("Llm.Credential.Default", TokenCanary);

        await _store.SaveAsync(options);

        // Find the DPAPI payload file (one of the SHA-256-named
        // files in the secrets directory).
        string secretsDir = Path.Combine(_paths.Config, "secrets");
        string payloadFile = Directory.EnumerateFiles(secretsDir, "*",
                SearchOption.TopDirectoryOnly)
            .First();

        byte[] bytes = await File.ReadAllBytesAsync(payloadFile);
        bytes[^1] ^= 0xFF;
        await File.WriteAllBytesAsync(payloadFile, bytes);

        await Assert.ThrowsAnyAsync<Exception>(() => _store.LoadAsync());
    }

    [Fact]
    public async Task Reference_document_with_wrong_schema_version_is_rejected()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.None);
        await _store.SaveAsync(options);

        string json = await File.ReadAllTextAsync(_store.ReferenceFilePath);
        // Replace schema version with 999.
        string tampered = json.Replace("\"SchemaVersion\": 1", "\"SchemaVersion\": 999");
        await File.WriteAllTextAsync(_store.ReferenceFilePath, tampered);

        await Assert.ThrowsAsync<InvalidDataException>(() => _store.LoadAsync());
    }

    [Fact]
    public async Task Clear_removes_reference_and_dpapi_payload()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default");
        _secretStore.Save("Llm.Credential.Default", TokenCanary);

        await _store.SaveAsync(options);
        await _store.ClearAsync();

        Assert.False(File.Exists(_store.ReferenceFilePath));
        LlmEndpointOptions? loaded = await _store.LoadAsync();
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Load_returns_null_when_no_reference_exists()
    {
        LlmEndpointOptions? loaded = await _store.LoadAsync();
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Recursive_scan_finds_no_plaintext_canary_in_config_or_temp()
    {
        var options = LlmEndpointOptions.Create(
            baseUri: new Uri($"https://{HostCanary}.internal.example/"),
            chatCompletionsPath: "/v1/chat/completions",
            model: ModelCanary,
            reference: "Llm.Endpoint.Default",
            authMode: LlmAuthMode.Bearer,
            credentialReference: "Llm.Credential.Default",
            customHeaderName: HeaderCanary);
        _secretStore.Save("Llm.Credential.Default", TokenCanary);
        await _store.SaveAsync(options);

        // Drop a temp file that should never contain the canary.
        Directory.CreateDirectory(_paths.Temp);
        await File.WriteAllTextAsync(Path.Combine(_paths.Temp, "scratch.txt"),
            "Some user data with no canary.");

        foreach (string file in Directory.EnumerateFiles(
            _paths.BasePath, "*", SearchOption.AllDirectories))
        {
            byte[] bytes = await File.ReadAllBytesAsync(file);
            string text = Encoding.UTF8.GetString(bytes);
            Assert.DoesNotContain(HostCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(ModelCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(HeaderCanary, text, StringComparison.Ordinal);
            Assert.DoesNotContain(TokenCanary, text, StringComparison.Ordinal);
        }
    }
}