using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Stores LLM API credentials via the P4 DPAPI <see cref="ISecretStore"/>
/// and exposes them only as a disposable sensitive buffer at request
/// creation time. Callers are expected to wrap the buffer in
/// <c>using</c>, hand it to the <see cref="OpenAiHttpClientFactory"/>
/// for the duration of one HTTP request, and let the buffer be zeroed.
///
/// No method in this class exposes the credential value through
/// <c>ToString</c>, exception messages, or log events. The
/// <c>ILlmCredentialStore</c> surface only references the credential by
/// its logical name.
/// </summary>
public interface ILlmCredentialStore
{
    /// <summary>Persists a credential under the supplied logical name.</summary>
    void SaveCredential(string logicalName, string value);

    /// <summary>Removes the credential with the supplied logical name.</summary>
    void DeleteCredential(string logicalName);

    /// <summary>
    /// Opens the credential as a disposable, zero-on-dispose buffer.
    /// The buffer is the only view in which the credential value is
    /// allowed to live. Throws when <paramref name="logicalName"/>
    /// does not exist or when the configured auth mode is
    /// <see cref="LlmAuthMode.None"/>.
    /// </summary>
    SensitiveCredentialBuffer OpenCredential(LlmEndpointOptions options);

    /// <summary>
    /// Returns true if a credential with this logical name exists.
    /// </summary>
    bool HasCredential(string logicalName);
}

/// <summary>
/// Default DPAPI-backed implementation. Stores the credential under
/// the supplied logical name in the
/// <see cref="WindowsDpapiSecretStore"/>; never logs the value.
/// </summary>
public sealed class LlmCredentialStore : ILlmCredentialStore
{
    private readonly ISecretStore _store;

    public LlmCredentialStore(ISecretStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    public void SaveCredential(string logicalName, string value)
    {
        ValidateName(logicalName);
        ArgumentNullException.ThrowIfNull(value);
        _store.Save(logicalName, value);
    }

    public void DeleteCredential(string logicalName)
    {
        ValidateName(logicalName);
        _store.Delete(logicalName);
    }

    public bool HasCredential(string logicalName)
    {
        ValidateName(logicalName);
        try
        {
            _store.Load(logicalName);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    public SensitiveCredentialBuffer OpenCredential(LlmEndpointOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.AuthMode == LlmAuthMode.None)
            throw new InvalidOperationException(
                "No credential is required for the configured auth mode.");
        if (string.IsNullOrEmpty(options.CredentialReference))
            throw new InvalidOperationException(
                "Endpoint options do not reference a credential.");

        string raw;
        try
        {
            raw = _store.Load(options.CredentialReference);
        }
        catch (FileNotFoundException ex)
        {
            throw new InvalidOperationException(
                "Referenced credential was not found in the secret store.", ex);
        }

        return new SensitiveCredentialBuffer(raw);
    }

    private static void ValidateName(string logicalName)
    {
        if (string.IsNullOrWhiteSpace(logicalName))
            throw new ArgumentException(
                "Credential logical name is required.", nameof(logicalName));
    }
}

/// <summary>
/// Disposable buffer for a UTF-8 credential. The byte view is
/// zeroed on disposal; the string view is replaced with an empty
/// string. After <see cref="Dispose"/>, callers must not dereference
/// <see cref="Value"/>.
/// </summary>
public sealed class SensitiveCredentialBuffer : IDisposable
{
    private byte[]? _bytes;
    private string? _value;
    private bool _disposed;

    internal SensitiveCredentialBuffer(string value)
    {
        _value = value;
        _bytes = Encoding.UTF8.GetBytes(value);
    }

    /// <summary>
    /// The credential as a UTF-8 byte buffer. The buffer is mutated
    /// in place on disposal. Do not retain the reference after
    /// <see cref="Dispose"/>.
    /// </summary>
    public ReadOnlySpan<byte> Utf8Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes!;
        }
    }

    /// <summary>
    /// Convenience accessor for the credential as a string. Do not
    /// log or persist the value — this exists so the HTTP factory can
    /// create a header value without an extra allocation. The
    /// underlying string is cleared on <see cref="Dispose"/>.
    /// </summary>
    public string Value
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _value!;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_bytes is not null)
        {
            CryptographicOperations.ZeroMemory(_bytes);
            _bytes = null;
        }
        _value = string.Empty;
    }
}
