using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecurityReview.ContractTests.Llm;

/// <summary>
/// In-process mock of the approved intranet LLM endpoint. Uses a
/// raw <see cref="TcpListener"/> so tests can issue requests directly
/// to <c>127.0.0.1</c> and observe the wire behavior of
/// <c>ExactOriginHttpMessageHandler</c>. The mock supports the cases
/// required by the brief: valid 200, 401/403/404/429/500, redirect,
/// Windows integrated-auth challenge, cookies, AIA/CRL/OCSP canary
/// URLs in the certificate, and certificate-validation failures.
///
/// All listeners bind to a random local port (loopback only). The
/// mock never accepts a non-loopback connection.
/// </summary>
public sealed class MockOpenAiServer : IAsyncDisposable, IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly ConcurrentBag<RecordedRequest> _requests = new();
    private readonly Func<HttpRequestContext, Task<HttpResponseDescriptor>> _handler;
    private readonly X509Certificate2? _tlsCertificate;
    private readonly List<string> _canaryEndpoints = new();

    public int Port { get; }
    public string Origin => _tlsCertificate is null
        ? $"http://127.0.0.1:{Port}"
        : $"https://127.0.0.1:{Port}";
    public string HttpOrigin => $"http://127.0.0.1:{Port}";
    public string ChatCompletionsPath { get; }

    /// <summary>
    /// Build a mock server with the supplied request handler and
    /// (optionally) a TLS certificate to use for HTTPS. Pass
    /// <paramref name="tlsCertificate"/> as <c>null</c> to expose
    /// plain HTTP only (e.g. for the redirect and proxy-env tests).
    /// </summary>
    public MockOpenAiServer(
        Func<HttpRequestContext, Task<HttpResponseDescriptor>> handler,
        X509Certificate2? tlsCertificate = null,
        string chatCompletionsPath = "/v1/chat/completions")
    {
        _handler = handler;
        _tlsCertificate = tlsCertificate;
        ChatCompletionsPath = chatCompletionsPath;

        _listener = new TcpListener(IPAddress.Loopback, port: 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>All requests received, in arrival order.</summary>
    public IReadOnlyCollection<RecordedRequest> Requests => _requests.ToArray();

    /// <summary>List of canary host names extracted from the server cert.</summary>
    public IReadOnlyList<string> CanaryEndpoints => _canaryEndpoints;

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            _ = Task.Run(() => HandleClientAsync(client));
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using (client)
        {
            Stream inner = client.GetStream();
            Stream wire = inner;
            bool useTls = _tlsCertificate is not null;
            SslStream? ssl = null;
            if (useTls)
            {
                ssl = new SslStream(inner, leaveInnerStreamOpen: false);
                try
                {
                    var options = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _tlsCertificate,
                        ClientCertificateRequired = false,
                    };
                    await ssl.AuthenticateAsServerAsync(options)
                        .ConfigureAwait(false);
                    wire = ssl;
                }
                catch
                {
                    return;
                }
            }

            try
            {
                var reader = new StreamReader(wire, Encoding.ASCII, false, 8192, leaveOpen: true);
                string requestLine = await reader.ReadLineAsync().ConfigureAwait(false)
                    ?? string.Empty;
                if (string.IsNullOrEmpty(requestLine))
                    return;

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                while (true)
                {
                    string? line = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (line is null) return;
                    if (line.Length == 0) break;
                    int colon = line.IndexOf(':');
                    if (colon <= 0) continue;
                    string name = line[..colon].Trim();
                    string value = line[(colon + 1)..].Trim();
                    headers[name] = value;
                }

                int contentLength = 0;
                if (headers.TryGetValue("Content-Length", out var cl) &&
                    int.TryParse(cl, out var parsed))
                {
                    contentLength = parsed;
                }
                string body = string.Empty;
                if (contentLength > 0)
                {
                    var buf = new char[contentLength];
                    int read = 0;
                    while (read < contentLength)
                    {
                        int n = await reader.ReadAsync(buf, read, contentLength - read)
                            .ConfigureAwait(false);
                        if (n <= 0) break;
                        read += n;
                    }
                    body = new string(buf, 0, read);
                }

                var ctx = new HttpRequestContext(
                    requestLine, headers, body, client.Client.RemoteEndPoint as IPEndPoint);
                _requests.Add(new RecordedRequest(ctx, DateTimeOffset.UtcNow));

                HttpResponseDescriptor response = await _handler(ctx).ConfigureAwait(false);
                string statusText = response.StatusCode switch
                {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    302 => "Found",
                    301 => "Moved Permanently",
                    _ => "Status",
                };
                var headerLines = new StringBuilder();
                headerLines
                    .Append("HTTP/1.1 ")
                    .Append(response.StatusCode)
                    .Append(' ')
                    .Append(statusText)
                    .Append("\r\n");
                headerLines
                    .Append("Content-Type: ")
                    .Append(response.ContentType ?? "application/json")
                    .Append("\r\n");
                headerLines
                    .Append("Content-Length: ")
                    .Append(Encoding.UTF8.GetByteCount(response.Body))
                    .Append("\r\n");
                headerLines.Append("Connection: close\r\n");
                if (response.Headers is not null)
                {
                    foreach (var kv in response.Headers)
                    {
                        headerLines
                            .Append(kv.Key)
                            .Append(": ")
                            .Append(kv.Value)
                            .Append("\r\n");
                    }
                }
                headerLines.Append("\r\n");

                byte[] headerBytes = Encoding.ASCII.GetBytes(headerLines.ToString());
                byte[] bodyBytes = Encoding.UTF8.GetBytes(response.Body);
                await wire.WriteAsync(headerBytes).ConfigureAwait(false);
                await wire.WriteAsync(bodyBytes).ConfigureAwait(false);
                await wire.FlushAsync().ConfigureAwait(false);
            }
            catch
            {
                // Drop the connection on any error.
            }
            finally
            {
                ssl?.Dispose();
            }
        }
    }

    /// <summary>Extract canary URLs from the configured certificate.</summary>
    public void RecordCanaryEndpointsFromCertificate()
    {
        if (_tlsCertificate is null) return;
        foreach (string url in _tlsCertificate.GetCanaryUrls())
        {
            _canaryEndpoints.Add(url);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* best effort */ }
        try { await _acceptLoop.ConfigureAwait(false); } catch { /* ignore */ }
        _cts.Dispose();
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
}

/// <summary>
/// Captured request context passed to the per-test handler.
/// </summary>
public sealed record HttpRequestContext(
    string RequestLine,
    IReadOnlyDictionary<string, string> Headers,
    string Body,
    IPEndPoint? RemoteEndPoint);

public sealed record RecordedRequest(
    HttpRequestContext Context,
    DateTimeOffset ReceivedAtUtc);

public sealed record HttpResponseDescriptor(
    int StatusCode,
    string Body,
    string? ContentType = null,
    IReadOnlyDictionary<string, string>? Headers = null);

/// <summary>
/// Generates self-signed certificates with AIA/CRL/OCSP canary URLs
/// embedded so the test can prove that no
/// AIA/CRL/OCSP download is attempted by the exact-origin HTTP
/// stack.
/// </summary>
internal static class X509Helper
{
    public static X509Certificate2 BuildSelfSigned(
        string subject,
        string? dnsName = null,
        IEnumerable<string>? canaryUrls = null)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={subject}", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        if (dnsName is not null)
        {
            var san = new SubjectAlternativeNameBuilder();
            if (IPAddress.TryParse(dnsName, out var ipAddress))
                san.AddIpAddress(ipAddress);
            else
                san.AddDnsName(dnsName);
            req.CertificateExtensions.Add(san.Build());
        }
        if (canaryUrls is not null)
        {
            // Embed canary URLs in the AIA extension so a chain
            // builder that ignores DisableCertificateDownloads would
            // try to reach them.
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            foreach (string url in canaryUrls)
            {
                writer.PushSequence();
                writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
                writer.WriteCharacterString(
                    UniversalTagNumber.IA5String,
                    url,
                    new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.PopSequence();
            }
            writer.PopSequence();
            req.CertificateExtensions.Add(
                new X509Extension(
                    "1.3.6.1.5.5.7.1.1",
                    writer.Encode(),
                    critical: false));
        }
        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
        X509KeyStorageFlags storageFlags = X509KeyStorageFlags.Exportable;
        if (!OperatingSystem.IsMacOS())
            storageFlags |= X509KeyStorageFlags.EphemeralKeySet;

        return X509CertificateLoader.LoadPkcs12(
            cert.Export(X509ContentType.Pfx),
            password: null,
            storageFlags);
    }
}

internal static class X509CertificateExtensions
{
    public static IEnumerable<string> GetCanaryUrls(this X509Certificate2 cert)
    {
        var urls = new List<string>();
        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1")
            {
                try
                {
                    var reader = new AsnReader(ext.RawData, AsnEncodingRules.DER);
                    var descriptions = reader.ReadSequence();
                    while (descriptions.HasData)
                    {
                        var description = descriptions.ReadSequence();
                        _ = description.ReadObjectIdentifier();
                        urls.Add(description.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            new Asn1Tag(TagClass.ContextSpecific, 6)));
                    }
                }
                catch (AsnContentException)
                {
                    // Ignore malformed test-only metadata.
                }
            }
        }
        return urls;
    }
}
