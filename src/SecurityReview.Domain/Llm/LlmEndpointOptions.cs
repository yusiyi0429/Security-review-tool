using System.Text;

namespace SecurityReview.Domain.Llm;

/// <summary>
/// Validated runtime configuration for a single approved intranet LLM
/// endpoint. The origin (scheme + host + effective port) is locked at
/// construction time and used by <c>ExactOriginHttpMessageHandler</c> to
/// reject any request that would otherwise escape the corporate HTTPS
/// surface. The credential referenced by <see cref="CredentialReference"/>
/// is stored separately in DPAPI — this record never embeds plaintext
/// tokens, model identifiers, or host names in any string representation.
/// </summary>
public sealed record LlmEndpointOptions
{
    private const int MaxUrlLength = 2048;
    private const int MinModelLength = 1;
    private const int MaxModelLength = 256;
    private const int MinTimeoutSeconds = 1;
    private const int MaxTimeoutSeconds = 120;
    private const int MinConcurrencyLimit = 1;
    private const int MaxConcurrencyLimit = 4;
    private const int DefaultConcurrency = 2;
    private const int DefaultTimeoutSeconds = 30;

    /// <summary>Default chat completions path. Must remain root-relative.</summary>
    public const string DefaultChatCompletionsPath = "/v1/chat/completions";

    /// <summary>
    /// Validated base URI. Scheme, host, port, and base path are frozen.
    /// </summary>
    public Uri BaseUri { get; }

    /// <summary>
    /// Root-relative chat completions path; must begin with "/" and stay
    /// inside the configured base path.
    /// </summary>
    public string ChatCompletionsPath { get; }

    /// <summary>Configured model identifier (1–256 printable non-control chars).</summary>
    public string Model { get; }

    /// <summary>Selected authentication mode.</summary>
    public LlmAuthMode AuthMode { get; }

    /// <summary>Structured-response strategy (default: <c>JsonSchema</c>).</summary>
    public LlmResponseFormatMode ResponseFormatMode { get; }

    /// <summary>
    /// If true (default), the client pins <c>temperature=0</c> on every
    /// request so results stay deterministic across hosts and retries.
    /// </summary>
    public bool SendTemperatureZero { get; }

    /// <summary>
    /// Custom HTTP header name (only set when <see cref="AuthMode"/> is
    /// <see cref="LlmAuthMode.CustomHeader"/>). Validated against a
    /// deny-list of transport-controlled header names.
    /// </summary>
    public string? CustomHeaderName { get; }

    /// <summary>
    /// Logical name (not the value) of the DPAPI-protected credential
    /// used to authenticate. Resolved by an external <c>ISecretStore</c>
    /// at request creation time; never serialized here.
    /// </summary>
    public string? CredentialReference { get; }

    /// <summary>Per-request timeout. Bounded 1–120 seconds.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>Maximum concurrent in-flight requests. Bounded 1–4.</summary>
    public int MaxConcurrency { get; }

    private LlmEndpointOptions(
        Uri baseUri,
        string chatCompletionsPath,
        string model,
        LlmAuthMode authMode,
        LlmResponseFormatMode responseFormatMode,
        bool sendTemperatureZero,
        string? customHeaderName,
        string? credentialReference,
        TimeSpan timeout,
        int maxConcurrency)
    {
        BaseUri = baseUri;
        ChatCompletionsPath = chatCompletionsPath;
        Model = model;
        AuthMode = authMode;
        ResponseFormatMode = responseFormatMode;
        SendTemperatureZero = sendTemperatureZero;
        CustomHeaderName = customHeaderName;
        CredentialReference = credentialReference;
        Timeout = timeout;
        MaxConcurrency = maxConcurrency;
    }

    /// <summary>
    /// The approved origin is the base authority only. Anything else
    /// (path, query, fragment, userinfo) is stripped so the comparison
    /// in <c>ExactOriginHttpMessageHandler</c> is exact-equal.
    /// </summary>
    public Uri ApprovedOrigin => new(BaseUri.GetLeftPart(UriPartial.Authority));

    /// <summary>
    /// Builds validated options. In release builds the base URL must be
    /// HTTPS. In debug builds loopback HTTP is allowed when
    /// <paramref name="allowLoopbackHttp"/> is true — the same escape
    /// hatch is consumed by the exact-origin HTTP handler.
    /// </summary>
    public static LlmEndpointOptions Create(
        Uri baseUri,
        string? chatCompletionsPath = null,
        string? model = null,
        string? reference = null,
        LlmAuthMode authMode = LlmAuthMode.None,
        LlmResponseFormatMode responseFormatMode = LlmResponseFormatMode.JsonSchema,
        bool sendTemperatureZero = true,
        string? customHeaderName = null,
        string? credentialReference = null,
        TimeSpan? timeout = null,
        int? maxConcurrency = null,
        bool allowLoopbackHttp = false)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        if (!baseUri.IsAbsoluteUri)
            throw new ArgumentException("Base URI must be absolute.", nameof(baseUri));
        if (string.IsNullOrEmpty(baseUri.Host))
            throw new ArgumentException("Base URI host is required.", nameof(baseUri));
        if (baseUri.AbsoluteUri.Length > MaxUrlLength)
            throw new ArgumentException(
                $"Base URI exceeds {MaxUrlLength} characters.", nameof(baseUri));
        if (baseUri.UserInfo.Length > 0)
            throw new ArgumentException(
                "Base URI must not contain userinfo or embedded credentials.", nameof(baseUri));
        if (!string.IsNullOrEmpty(baseUri.Fragment))
            throw new ArgumentException(
                "Base URI must not contain a fragment.", nameof(baseUri));
        if (!string.IsNullOrEmpty(baseUri.Query))
            throw new ArgumentException(
                "Base URI must not contain a query string.", nameof(baseUri));
        if (baseUri.Host.Contains('*'))
            throw new ArgumentException(
                "Base URI host must not contain wildcards.", nameof(baseUri));

        ValidateScheme(baseUri, allowLoopbackHttp);

        string path = chatCompletionsPath ?? DefaultChatCompletionsPath;
        ValidateChatCompletionsPath(path, baseUri);

        string resolvedModel = model ?? throw new ArgumentException(
            "Model is required.", nameof(model));
        ValidateModel(resolvedModel);

        ValidateAuth(authMode, customHeaderName);

        TimeSpan resolvedTimeout = timeout ?? TimeSpan.FromSeconds(DefaultTimeoutSeconds);
        if (resolvedTimeout < TimeSpan.FromSeconds(MinTimeoutSeconds) ||
            resolvedTimeout > TimeSpan.FromSeconds(MaxTimeoutSeconds))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout),
                $"Timeout must be {MinTimeoutSeconds}–{MaxTimeoutSeconds} seconds.");
        }

        int resolvedConcurrency = maxConcurrency ?? DefaultConcurrency;
        if (resolvedConcurrency < MinConcurrencyLimit || resolvedConcurrency > MaxConcurrencyLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrency),
                $"MaxConcurrency must be {MinConcurrencyLimit}–{MaxConcurrencyLimit}.");
        }

        _ = reference; // Reserved for future routing — not used in this record.

        return new LlmEndpointOptions(
            baseUri, path, resolvedModel, authMode, responseFormatMode,
            sendTemperatureZero, customHeaderName, credentialReference,
            resolvedTimeout, resolvedConcurrency);
    }

    private static void ValidateScheme(Uri baseUri, bool allowLoopbackHttp)
    {
        if (string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return;

        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Base URI scheme '{baseUri.Scheme}' is not supported.", nameof(baseUri));
        }

        // HTTP base URIs are loopback-only and only allowed in DEBUG builds.
#if !DEBUG
        throw new ArgumentException(
            "Base URI scheme must be https in release builds.", nameof(baseUri));
#else
        if (!allowLoopbackHttp)
            throw new ArgumentException(
                "HTTP base URIs are only allowed in DEBUG with --allow-loopback-http.",
                nameof(baseUri));
        if (!IsLoopbackHost(baseUri.Host))
            throw new ArgumentException(
                "HTTP base URIs may only target a loopback host.", nameof(baseUri));
#endif
    }

    private static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (System.Net.IPAddress.TryParse(host, out var ip))
            return System.Net.IPAddress.IsLoopback(ip);
        return false;
    }

    private static void ValidateChatCompletionsPath(string path, Uri baseUri)
    {
        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("Chat completions path is required.", nameof(path));
        if (!path.StartsWith('/'))
            throw new ArgumentException(
                "Chat completions path must be root-relative (start with '/').", nameof(path));
        if (path.Contains('\r') || path.Contains('\n'))
            throw new ArgumentException(
                "Chat completions path must not contain CR/LF.", nameof(path));
        if (path.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException(
                "Chat completions path must not contain '..' segments.", nameof(path));

        string basePath = baseUri.AbsolutePath;
        if (!string.Equals(basePath, "/", StringComparison.Ordinal))
        {
            if (!path.StartsWith(basePath, StringComparison.Ordinal))
                throw new ArgumentException(
                    $"Chat completions path must start with the configured base path '{basePath}'.",
                    nameof(path));
        }
    }

    private static void ValidateModel(string model)
    {
        const string param = "model";
        if (string.IsNullOrEmpty(model) || string.IsNullOrWhiteSpace(model))
            throw new ArgumentException("Model is required.", param);
        if (model.Length > MaxModelLength)
            throw new ArgumentException(
                $"Model length must be ≤{MaxModelLength} characters.", param);
        foreach (char c in model)
        {
            if (c < 0x20 || c == 0x7F)
                throw new ArgumentException(
                    "Model must contain only printable non-control characters.", param);
        }
    }

    private static readonly HashSet<string> ForbiddenCustomHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host",
        "Content-Length",
        "Connection",
        "Proxy-Authorization",
        "Proxy-Connection",
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
    };

    private static void ValidateAuth(LlmAuthMode authMode, string? customHeaderName)
    {
        const string headerParam = "customHeaderName";

        if (authMode == LlmAuthMode.None)
        {
            if (customHeaderName is not null)
                throw new ArgumentException(
                    "Custom header name requires CustomHeader auth mode.", headerParam);
            return;
        }

        if (authMode == LlmAuthMode.Bearer)
        {
            if (customHeaderName is not null)
                throw new ArgumentException(
                    "Bearer auth does not accept a custom header name.", headerParam);
            return;
        }

        // CustomHeader mode
        if (string.IsNullOrEmpty(customHeaderName))
            throw new ArgumentException(
                "CustomHeader auth mode requires a header name.", headerParam);

        foreach (char c in customHeaderName)
        {
            // RFC 7230 token character set: ! # $ % & ' * + - . ^ _ ` | ~ DIGIT ALPHA
            bool ok = (c is >= 'A' and <= 'Z')
                   || (c is >= 'a' and <= 'z')
                   || (c is >= '0' and <= '9')
                   || "!#$%&'*+-.^_`|~".Contains(c);
            if (!ok)
                throw new ArgumentException(
                    $"Custom header name '{customHeaderName}' contains invalid token characters.",
                    headerParam);
        }

        if (ForbiddenCustomHeaders.Contains(customHeaderName))
            throw new ArgumentException(
                $"Custom header name '{customHeaderName}' is on the deny-list.", headerParam);
    }

    /// <summary>
    /// Privacy-preserving <c>ToString</c>: returns only the option kind
    /// and the approved origin fingerprint. The model, credential
    /// reference, base path, and host in human-readable form are never
    /// emitted. The full origin is reduced to a 16-hex hash prefix so
    /// logs can correlate without leaking the URL.
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append("LlmEndpointOptions(");
        sb.Append("AuthMode=").Append(AuthMode);
        sb.Append(", ResponseFormatMode=").Append(ResponseFormatMode);
        sb.Append(", MaxConcurrency=").Append(MaxConcurrency);
        sb.Append(", TimeoutSeconds=").Append((int)Timeout.TotalSeconds);
        sb.Append(", OriginFingerprint=").Append(OriginFingerprint());
        sb.Append(')');
        return sb.ToString();
    }

    /// <summary>
    /// Non-reversible 16-hex fingerprint of the approved origin for use
    /// in diagnostic events and audit logs. The full host:port is not
    /// embedded.
    /// </summary>
    public string OriginFingerprint()
    {
        byte[] hash = System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(ApprovedOrigin.AbsoluteUri.ToLowerInvariant()));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}