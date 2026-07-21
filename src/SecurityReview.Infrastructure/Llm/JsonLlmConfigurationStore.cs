using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Llm;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// JSON-backed implementation of <see cref="ILlmConfigurationStore"/>.
/// The on-disk reference document is intentionally minimal: it
/// contains the schema version, the name of the DPAPI-protected entry
/// that holds the actual options, a 16-hex origin fingerprint, and a
/// UTC timestamp. The protected payload is JSON with
/// <see cref="JsonSerializerOptions"/> that omits any null field — a
/// pass-through leak audit can therefore scan the reference document
/// for forbidden tokens and the underlying payload is encrypted at
/// rest.
/// </summary>
public sealed class JsonLlmConfigurationStore : ILlmConfigurationStore
{
    /// <summary>Schema version of the on-disk reference document.</summary>
    public const int SchemaVersion = 1;

    /// <summary>Default logical name for the DPAPI-protected options payload.</summary>
    public const string DefaultConfigReference = "Llm.Endpoint.Default";

    private static readonly JsonSerializerOptions ReferenceJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions PayloadJsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IApplicationPaths _paths;
    private readonly ISecretStore _secrets;
    private readonly string _configReferenceName;
    private readonly IValueFingerprintService _fingerprints;

    /// <summary>
    /// Constructs the store using the supplied paths and secret store.
    /// </summary>
    public JsonLlmConfigurationStore(
        IApplicationPaths paths,
        ISecretStore secrets,
        IValueFingerprintService fingerprints,
        string configReferenceName = DefaultConfigReference)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(fingerprints);
        if (string.IsNullOrWhiteSpace(configReferenceName))
            throw new ArgumentException(
                "Config reference name is required.", nameof(configReferenceName));

        _paths = paths;
        _secrets = secrets;
        _fingerprints = fingerprints;
        _configReferenceName = configReferenceName;
    }

    /// <summary>Path to the atomic on-disk reference document.</summary>
    public string ReferenceFilePath => Path.Combine(_paths.Config, "llm-endpoint.json");

    public async Task<LlmConfigurationReference> SaveAsync(
        LlmEndpointOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();

        // Build the protected payload — this is a *string* of JSON
        // that the secret store will DPAPI-encrypt and store under
        // _configReferenceName. No host, model, or header value is
        // ever written to the reference document.
        string payloadJson = JsonSerializer.Serialize(ToPayload(options), PayloadJsonOptions);
        _secrets.Save(_configReferenceName, payloadJson);

        // Compute the origin fingerprint from the approved origin.
        // Use the same algorithm as LlmEndpointOptions.OriginFingerprint.
        string fingerprint = options.OriginFingerprint();

        var reference = new LlmConfigurationReference(
            SchemaVersion: SchemaVersion,
            ConfigReference: _configReferenceName,
            EndpointFingerprint: fingerprint,
            UpdatedAtUtc: DateTimeOffset.UtcNow);

        await WriteReferenceAtomicAsync(reference, cancellationToken).ConfigureAwait(false);
        return reference;
    }

    public async Task<LlmEndpointOptions?> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(ReferenceFilePath))
            return null;

        LlmConfigurationReference reference;
        try
        {
            string json = await File.ReadAllTextAsync(ReferenceFilePath, cancellationToken)
                .ConfigureAwait(false);
            reference = JsonSerializer.Deserialize<LlmConfigurationReference>(
                json, ReferenceJsonOptions)
                ?? throw new InvalidDataException(
                    "LLM reference document is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                "LLM reference document is not valid JSON.", ex);
        }

        if (reference.SchemaVersion != SchemaVersion)
            throw new InvalidDataException(
                $"Unsupported LLM reference schema version {reference.SchemaVersion}.");

        string payload;
        try
        {
            payload = _secrets.Load(reference.ConfigReference);
        }
        catch (FileNotFoundException ex)
        {
            throw new InvalidDataException(
                "Referenced LLM configuration payload is missing.", ex);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidDataException(
                "Referenced LLM configuration payload could not be decrypted.", ex);
        }

        LlmConfigurationPayload? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<LlmConfigurationPayload>(
                payload, PayloadJsonOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                "LLM configuration payload is not valid JSON.", ex);
        }
        if (parsed is null)
            throw new InvalidDataException(
                "LLM configuration payload is empty.");

        return FromPayload(parsed);
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(ReferenceFilePath))
        {
            File.Delete(ReferenceFilePath);
        }
        try
        {
            _secrets.Delete(_configReferenceName);
        }
        catch (FileNotFoundException)
        {
            // Already gone.
        }
        await Task.CompletedTask;
    }

    private async Task WriteReferenceAtomicAsync(
        LlmConfigurationReference reference, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_paths.Config);
        string json = JsonSerializer.Serialize(reference, ReferenceJsonOptions);
        string tmp = ReferenceFilePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            await File.WriteAllBytesAsync(tmp, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(tmp, ReferenceFilePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
            throw;
        }
    }

    private static LlmConfigurationPayload ToPayload(LlmEndpointOptions options)
    {
        return new LlmConfigurationPayload
        {
            BaseUri = options.BaseUri.AbsoluteUri,
            ChatCompletionsPath = options.ChatCompletionsPath,
            Model = options.Model,
            AuthMode = options.AuthMode,
            ResponseFormatMode = options.ResponseFormatMode,
            SendTemperatureZero = options.SendTemperatureZero,
            CustomHeaderName = options.CustomHeaderName,
            CredentialReference = options.CredentialReference,
            TimeoutSeconds = (int)options.Timeout.TotalSeconds,
            MaxConcurrency = options.MaxConcurrency,
        };
    }

    private static LlmEndpointOptions FromPayload(LlmConfigurationPayload payload)
    {
        string baseUri = payload.BaseUri
            ?? throw new InvalidDataException("LLM payload is missing BaseUri.");
        return LlmEndpointOptions.Create(
            baseUri: new Uri(baseUri),
            chatCompletionsPath: payload.ChatCompletionsPath,
            model: payload.Model,
            reference: payload.CredentialReference,
            authMode: payload.AuthMode,
            responseFormatMode: payload.ResponseFormatMode,
            sendTemperatureZero: payload.SendTemperatureZero,
            customHeaderName: payload.CustomHeaderName,
            credentialReference: payload.CredentialReference,
            timeout: TimeSpan.FromSeconds(payload.TimeoutSeconds),
            maxConcurrency: payload.MaxConcurrency);
    }

    /// <summary>
    /// The DPAPI-protected payload. Fields mirror
    /// <see cref="LlmEndpointOptions"/> and are mapped to/from it in
    /// <see cref="ToPayload"/> / <see cref="FromPayload"/>.
    /// </summary>
    internal sealed record LlmConfigurationPayload
    {
        public string? BaseUri { get; init; }
        public string? ChatCompletionsPath { get; init; }
        public string? Model { get; init; }
        public LlmAuthMode AuthMode { get; init; }
        public LlmResponseFormatMode ResponseFormatMode { get; init; }
        public bool SendTemperatureZero { get; init; }
        public string? CustomHeaderName { get; init; }
        public string? CredentialReference { get; init; }
        public int TimeoutSeconds { get; init; }
        public int MaxConcurrency { get; init; }
    }
}