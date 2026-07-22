using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Locked-down HTTP transport for the approved intranet LLM endpoint.
/// The handler wraps a <see cref="SocketsHttpHandler"/> with the
/// smallest set of sockets options that still meets OpenAI-style
/// request/response semantics, and gates every outgoing request against
/// the approved origin: scheme, host, effective port, and base path
/// must all match exactly (ordinal, case-insensitive). 3xx responses
/// are never followed. CR/LF in the request line or path is rejected
/// before the bytes leave the process. In debug builds only, HTTP is
/// accepted for loopback hosts when the process was started with the
/// <c>--allow-loopback-http</c> argument.
/// </summary>
public sealed class ExactOriginHttpMessageHandler : DelegatingHandler
{
    private const string LoopbackArgument = "--allow-loopback-http";

    private static readonly bool AllowLoopbackHttp = DetectLoopbackArgument();

    private readonly Uri _approvedOrigin;
    private readonly string _approvedBasePath;
    private readonly bool _allowLoopbackHttp;
    private readonly int _maxConnections;

    /// <summary>
    /// Builds the handler against the supplied <see cref="LlmEndpointOptions"/>.
    /// The handler disposes the inner <see cref="SocketsHttpHandler"/>
    /// when the <see cref="HttpMessageHandler"/> is disposed.
    /// </summary>
    public ExactOriginHttpMessageHandler(LlmEndpointOptions options)
        : this(BuildInnerHandler(options), options)
    {
    }

    /// <summary>
    /// Test seam that lets contract tests inject a pre-configured
    /// inner handler (e.g. to count attempts to change host).
    /// </summary>
    internal ExactOriginHttpMessageHandler(
        SocketsHttpHandler inner, LlmEndpointOptions options)
        : base(inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(options);

        _approvedOrigin = options.ApprovedOrigin;
        _approvedBasePath = NormalizeBasePath(options.BaseUri.AbsolutePath);
        _allowLoopbackHttp = ShouldAllowLoopback(options);
        _maxConnections = Math.Max(1, options.MaxConcurrency);
    }

    /// <summary>The approved scheme (lowercased).</summary>
    public string ApprovedScheme => _approvedOrigin.Scheme;

    /// <summary>The approved host (lowercased).</summary>
    public string ApprovedHost => _approvedOrigin.Host;

    /// <summary>The approved effective port.</summary>
    public int ApprovedPort => GetEffectivePort(_approvedOrigin);

    /// <summary>The approved base path (normalized, lowercased).</summary>
    public string ApprovedBasePath => _approvedBasePath;

    private static SocketsHttpHandler BuildInnerHandler(LlmEndpointOptions options)
    {
        var ssl = new SslClientAuthenticationOptions
        {
            // Keep Windows system trust/hostname validation. Do not set
            // RemoteCertificateValidationCallback — we do not accept
            // certificates the OS would otherwise reject.
            CertificateRevocationCheckMode = X509RevocationMode.Offline,
            // Disable chain-building AIA/CRL/OCSP downloads. Enterprise
            // roots and revocation data must be installed by policy.
            CertificateChainPolicy = new X509ChainPolicy
            {
                DisableCertificateDownloads = true,
                RevocationMode = X509RevocationMode.Offline,
            },
        };

        var inner = new SocketsHttpHandler
        {
            SslOptions = ssl,
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            PreAuthenticate = false,
            AutomaticDecompression = DecompressionMethods.None,
            ActivityHeadersPropagator = null,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            MaxConnectionsPerServer = Math.Max(1, options.MaxConcurrency),
        };
        // Explicitly null out credential/ICredentials paths; the defaults
        // would otherwise be picked up from the environment.
        inner.Credentials = null;
        return inner;
    }

    private static bool ShouldAllowLoopback(LlmEndpointOptions options)
    {
        if (options.AllowLoopbackHttpForTesting)
            return true;
#if !DEBUG
        return false;
#else
        return AllowLoopbackHttp;
#endif
    }

    private static bool DetectLoopbackArgument()
    {
        try
        {
            string[] args = Environment.GetCommandLineArgs();
            foreach (string a in args)
            {
                if (string.Equals(a, LoopbackArgument, StringComparison.Ordinal))
                    return true;
            }
        }
        catch
        {
            // Best-effort only — fall through.
        }
        return false;
    }

    /// <summary>
    /// Validates and forwards the request. Throws
    /// <see cref="InvalidOperationException"/> for any policy violation;
    /// the caller maps the exception to a stable
    /// <see cref="SecurityReview.Application.Llm.LlmConnectionTestFailureReason"/>.
    /// </summary>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);
        HttpResponseMessage response = await base.SendAsync(request, cancellationToken)
            .ConfigureAwait(false);
        ValidateResponse(response);
        return response;
    }

    protected override HttpResponseMessage Send(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);
        HttpResponseMessage response = base.Send(request, cancellationToken);
        ValidateResponse(response);
        return response;
    }

    private void ValidateRequest(HttpRequestMessage request)
    {
        Uri? uri = request.RequestUri;
        if (uri is null)
            throw new InvalidOperationException("Request URI is required.");

        // Scheme check
        if (!string.Equals(uri.Scheme, _approvedOrigin.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            if (!(_allowLoopbackHttp &&
                  string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                  IsLoopbackHost(uri.Host)))
            {
                throw new InvalidOperationException(
                    "Request scheme does not match the approved origin.");
            }
        }

        // Host check (ordinal-ignore-case)
        if (!string.Equals(uri.Host, _approvedOrigin.Host, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Request host does not match the approved origin.");

        // Effective port check
        if (GetEffectivePort(uri) != GetEffectivePort(_approvedOrigin))
            throw new InvalidOperationException(
                "Request port does not match the approved origin.");

        // Path / base path check
        string requestPath = NormalizeBasePath(uri.AbsolutePath);
        if (!IsUnderBasePath(requestPath, _approvedBasePath))
            throw new InvalidOperationException(
                "Request path escapes the approved base path.");

        // CR/LF check (covers request line, headers, path)
        ValidateNoControlChars(request);

        // Forbid credentials carried via URL userinfo
        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException(
                "Request URL must not contain userinfo or embedded credentials.");
    }

    private static void ValidateResponse(HttpResponseMessage response)
    {
        if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400)
            throw new InvalidOperationException(
                "Server returned a redirect; following is disabled.");
    }

    private static void ValidateNoControlChars(HttpRequestMessage request)
    {
        string url = request.RequestUri?.OriginalString ?? string.Empty;
        if (url.Contains('\r') || url.Contains('\n'))
            throw new InvalidOperationException(
                "Request URL contains CR/LF characters.");

        foreach (var header in request.Headers)
        {
            foreach (string value in header.Value)
            {
                if (value.Contains('\r') || value.Contains('\n'))
                    throw new InvalidOperationException(
                        $"Request header '{header.Key}' contains CR/LF characters.");
            }
        }

        if (request.Content is not null)
        {
            foreach (var header in request.Content.Headers)
            {
                foreach (string value in header.Value)
                {
                    if (value.Contains('\r') || value.Contains('\n'))
                        throw new InvalidOperationException(
                            $"Request content header '{header.Key}' contains CR/LF characters.");
                }
            }
        }
    }

    private static bool IsUnderBasePath(string path, string basePath)
    {
        if (string.Equals(basePath, "/", StringComparison.Ordinal))
            return path.Length > 0 && path[0] == '/';
        return path.StartsWith(basePath, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeBasePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "/";
        return path.ToLowerInvariant();
    }

    private static int GetEffectivePort(Uri uri)
    {
        if (!string.IsNullOrEmpty(uri.Host) && uri.Host.Contains(':'))
        {
            // Bracketed IPv6 literal — Uri.Port already handles the
            // host-name parsing for us when the URI is absolute.
        }
        if (uri.IsDefaultPort)
        {
            return string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? 443
                : 80;
        }
        return uri.Port;
    }

    private static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (IPAddress.TryParse(host, out var ip))
            return IPAddress.IsLoopback(ip);
        return false;
    }
}
