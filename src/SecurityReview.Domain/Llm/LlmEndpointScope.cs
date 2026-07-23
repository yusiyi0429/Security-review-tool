namespace SecurityReview.Domain.Llm;

/// <summary>
/// Declares the trust boundary for an LLM endpoint. Third-party endpoints require
/// HTTPS. Private-network endpoints may additionally use HTTP, provided the
/// transport connects only to an approved private or loopback address.
/// </summary>
public enum LlmEndpointScope
{
    /// <summary>A third-party or otherwise public API. HTTPS is mandatory.</summary>
    CloudApi = 0,

    /// <summary>An endpoint hosted on a trusted private network or this machine.</summary>
    PrivateNetwork = 1,
}
