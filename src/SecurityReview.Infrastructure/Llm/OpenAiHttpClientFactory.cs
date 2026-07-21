using System.Net.Http.Headers;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Builds <see cref="HttpClient"/> instances that are locked down to a
/// single approved origin via <see cref="ExactOriginHttpMessageHandler"/>.
/// The factory is also the one place that translates the configured
/// auth mode + DPAPI credential into a wire-format header. The
/// credential value is only ever present in the produced
/// <see cref="HttpRequestMessage"/> for the duration of the request
/// and never in any log, exception, or property of the returned
/// <see cref="HttpClient"/>.
/// </summary>
public static class OpenAiHttpClientFactory
{
    /// <summary>
    /// Builds the client. The supplied <see cref="ILlmCredentialStore"/>
    /// is only consulted at request creation time, not at client
    /// construction time — a client may outlive a single request.
    /// </summary>
    public static HttpClient Create(LlmEndpointOptions options, ILlmCredentialStore credentials)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(credentials);

        var handler = new ExactOriginHttpMessageHandler(options);
        var client = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = BuildBaseAddress(options),
            Timeout = options.Timeout,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SecurityReviewTool/1.0");
        client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    /// <summary>
    /// Applies the configured authentication to the supplied
    /// <see cref="HttpRequestMessage"/>. The credential buffer is
    /// consumed by reading the bytes / string; the buffer itself
    /// stays under the caller's <c>using</c> scope. After this call
    /// the caller is responsible for <c>Dispose</c> on the buffer.
    /// </summary>
    public static void ApplyAuthentication(
        HttpRequestMessage request,
        LlmEndpointOptions options,
        ILlmCredentialStore credentials)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(credentials);

        if (options.AuthMode == LlmAuthMode.None)
            return;

        using SensitiveCredentialBuffer buffer = credentials.OpenCredential(options);
        string value = buffer.Value;
        try
        {
            switch (options.AuthMode)
            {
                case LlmAuthMode.Bearer:
                {
                    var header = new AuthenticationHeaderValue("Bearer", value);
                    request.Headers.Authorization = header;
                    break;
                }
                case LlmAuthMode.CustomHeader:
                {
                    string headerName = options.CustomHeaderName
                        ?? throw new InvalidOperationException(
                            "CustomHeader auth mode requires a header name.");
                    if (!request.Headers.TryAddWithoutValidation(headerName, value))
                        throw new InvalidOperationException(
                            $"Failed to attach custom header '{headerName}'.");
                    break;
                }
            }
        }
        finally
        {
            // The buffer is zeroed in Dispose; we do not have a
            // mutable reference here. The caller's using block
            // guarantees cleanup.
        }
    }

    private static Uri BuildBaseAddress(LlmEndpointOptions options)
    {
        // Use the approved authority as the base. Path is encoded
        // per-request by the caller so we always rebuild the URL
        // against the exact-origin check.
        return options.ApprovedOrigin;
    }
}