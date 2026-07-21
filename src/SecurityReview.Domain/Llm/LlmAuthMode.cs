namespace SecurityReview.Domain.Llm;

/// <summary>
/// Authentication mode used when posting to the approved LLM origin.
/// The credential material is never embedded in this enum; the resolved
/// transport-layer secret is supplied by an external store at request
/// creation time and only lives in a disposable buffer.
/// </summary>
public enum LlmAuthMode
{
    /// <summary>No authentication. Used only for fully local/dev endpoints.</summary>
    None = 0,

    /// <summary>
    /// Standard HTTP bearer token via <c>Authorization: Bearer &lt;token&gt;</c>.
    /// </summary>
    Bearer = 1,

    /// <summary>
    /// Custom header carrying an opaque API key. The header name is
    /// validated by <see cref="LlmEndpointOptions"/> against an allow-list
    /// to keep it out of <c>Host</c>/<c>Content-Length</c>/<c>Connection</c>/
    /// <c>Proxy-*</c>/<c>Forwarded</c>/<c>X-Forwarded-*</c>.
    /// </summary>
    CustomHeader = 2,
}