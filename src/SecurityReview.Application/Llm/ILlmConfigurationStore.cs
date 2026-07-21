using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Persists LLM endpoint configuration without leaking host names, model
/// identifiers, or credential material to the on-disk surface. The store
/// holds only an atomic reference document
/// (<c>{schema_version, config_reference, endpoint_fingerprint, updated_at_utc}</c>);
/// the resolved options are protected by an <c>ISecretStore</c> under
/// the <c>config_reference</c> and are only ever loaded in-memory.
/// </summary>
public interface ILlmConfigurationStore
{
    /// <summary>
    /// Persists the supplied options. The host, model, header, and
    /// credential are never written to the returned reference document —
    /// they live in the referenced DPAPI-protected payload.
    /// </summary>
    Task<LlmConfigurationReference> SaveAsync(
        LlmEndpointOptions options,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads and validates the previously stored options, or returns
    /// <c>null</c> if no reference document exists yet. The
    /// reference document is verified against tampering before the
    /// underlying DPAPI payload is opened.
    /// </summary>
    Task<LlmEndpointOptions?> LoadAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the reference document and the underlying DPAPI payload.
    /// </summary>
    Task ClearAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// The atomic, privacy-preserving reference document written to disk.
/// It contains only a schema version, a secret-store name, an origin
/// fingerprint, and a UTC timestamp. The actual endpoint options
/// (host, port, base path, model, header name) live in the named
/// DPAPI-protected entry referenced by <see cref="ConfigReference"/>.
/// </summary>
public sealed record LlmConfigurationReference(
    int SchemaVersion,
    string ConfigReference,
    string EndpointFingerprint,
    DateTimeOffset UpdatedAtUtc);