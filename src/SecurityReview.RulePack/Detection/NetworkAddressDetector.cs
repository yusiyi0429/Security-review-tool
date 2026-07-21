using System.Net;
using System.Text.RegularExpressions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.RulePack.Detection;

/// <summary>
/// Classifies an IP address against known reserved ranges.
/// </summary>
public enum NetworkAddressClass
{
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Documentation,
    Benchmark
}

/// <summary>
/// A parsed network address with classification metadata.
/// </summary>
public readonly record struct ParsedNetworkAddress
{
    public string Value { get; init; }
    public NetworkAddressClass AddressClass { get; init; }
    public bool IsCidr { get; init; }
    public bool IsUrl { get; init; }
    public bool IsHostname { get; init; }
}

/// <summary>
/// Detects IP addresses (IPv4/IPv6), CIDR ranges, URLs, hostnames, and port numbers.
///
/// Classification uses IPAddress.TryParse and Uri.TryCreate after bounded tokenization.
/// RFC 1918, loopback, link-local, multicast, and documentation ranges are classified.
/// No DNS, WHOIS, HTTP, reachability, or reverse lookup is performed.
///
/// Approved examples are exact IP/CIDR/domain entries in the signed placeholder set;
/// matching against approved placeholders is done by the pipeline, not this detector.
/// </summary>
public sealed partial class NetworkAddressDetector : IDetector
{
    public DetectorKind Kind => DetectorKind.NetworkAddress;

    // Token boundary pattern: grab potential IP/URL/hostname tokens
    [GeneratedRegex(@"[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]+",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex CandidateTokenPattern();

    // IPv4 octet pattern for structural pre-filtering
    [GeneratedRegex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex IPv4Pattern();

    // IPv6 heuristic: hex digits + at least 2 colons, bounded by word boundaries.
    // This is intentionally loose for pre-filtering; TryParseIPv6 does final validation.
    [GeneratedRegex(@"\b[0-9a-fA-F]{1,4}:[0-9a-fA-F:]+[0-9a-fA-F](?:/\d{1,3})?\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex IPv6HeuristicPattern();

    // URL pattern
    [GeneratedRegex(@"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s,;!\}\{\)]*",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex UrlPattern();

    // Hostname heuristic (no protocol prefix)
    [GeneratedRegex(@"\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z][a-zA-Z0-9-]*)+\.(?:[a-zA-Z]{2,})(?::\d{1,5})?\b",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex HostnamePattern();

    public Task<IReadOnlyList<DetectionCandidate>> DetectAsync(
        ContentChunk chunk,
        RuleDefinition rule,
        DetectorDefinition detector,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(detector);

        cancellationToken.ThrowIfCancellationRequested();

        if (chunk.ContentKind == ContentKind.Binary)
            return Task.FromResult<IReadOnlyList<DetectionCandidate>>([]);

        int limit = detector.MaxMatchesPerChunk;
        bool includePrivate = detector.Parameters.TryGetValue("include_private", out string? priv)
            && string.Equals(priv, "true", StringComparison.OrdinalIgnoreCase);
        bool includePublic = detector.Parameters.TryGetValue("include_public", out string? pub)
            && string.Equals(pub, "true", StringComparison.OrdinalIgnoreCase);
        bool includeUrl = detector.Parameters.TryGetValue("include_url", out string? url)
            && string.Equals(url, "true", StringComparison.OrdinalIgnoreCase);

        string text = chunk.Text;
        var results = new List<DetectionCandidate>();
        var seenValues = new HashSet<string>(StringComparer.Ordinal);

        // Phase 1: IPv4 addresses
        foreach (var match in IPv4Pattern().EnumerateMatches(text))
        {
            if (results.Count >= limit) break;

            string value = text.Substring(match.Index, match.Length);
            if (!seenValues.Add(value)) continue;

            if (TryParseIPv4(value, out var parsed))
            {
                if (ShouldReport(parsed, includePrivate, includePublic))
                {
                    results.Add(CreateCandidate(chunk, rule, detector, parsed, text, match.Index, match.Length));
                }
            }
        }

        // Phase 2: IPv6 addresses
        foreach (var match in IPv6HeuristicPattern().EnumerateMatches(text))
        {
            if (results.Count >= limit) break;

            string value = text.Substring(match.Index, match.Length);
            if (!seenValues.Add(value)) continue;

            if (TryParseIPv6(value, out var parsed))
            {
                if (ShouldReport(parsed, includePrivate, includePublic))
                {
                    results.Add(CreateCandidate(chunk, rule, detector, parsed, text, match.Index, match.Length));
                }
            }
        }

        // Phase 3: URLs/hostnames
        if (includeUrl)
        {
            // Scan URLs first
            foreach (var match in UrlPattern().EnumerateMatches(text))
            {
                if (results.Count >= limit) break;

                string value = text.Substring(match.Index, match.Length);
                if (!seenValues.Add(value)) continue;

                if (TryParseUrlOrHostname(value, out var parsed))
                {
                    results.Add(CreateCandidate(chunk, rule, detector, parsed, text, match.Index, match.Length));
                }
            }

            // Then hostnames
            foreach (var match in HostnamePattern().EnumerateMatches(text))
            {
                if (results.Count >= limit) break;

                string value = text.Substring(match.Index, match.Length);
                if (!seenValues.Add(value)) continue;

                if (TryParseUrlOrHostname(value, out var parsed))
                {
                    results.Add(CreateCandidate(chunk, rule, detector, parsed, text, match.Index, match.Length));
                }
            }
        }

        return Task.FromResult<IReadOnlyList<DetectionCandidate>>(results);
    }

    public static bool TryParseIPv4(string token, out ParsedNetworkAddress parsed)
    {
        parsed = default;

        // Handle CIDR
        string addrPart = token;
        bool isCidr = false;
        int slashIdx = token.IndexOf('/');
        if (slashIdx > 0)
        {
            addrPart = token[..slashIdx];
            string prefixStr = token[(slashIdx + 1)..];
            if (!int.TryParse(prefixStr, out int prefix) || prefix < 0 || prefix > 32)
                return false;
            isCidr = true;
        }

        if (!IPAddress.TryParse(addrPart, out IPAddress? ip))
            return false;

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var addrClass = ClassifyIPv4(ip);

        parsed = new ParsedNetworkAddress
        {
            Value = token,
            AddressClass = addrClass,
            IsCidr = isCidr,
            IsUrl = false,
            IsHostname = false
        };

        return true;
    }

    public static bool TryParseIPv6(string token, out ParsedNetworkAddress parsed)
    {
        parsed = default;

        // Handle CIDR
        string addrPart = token;
        bool isCidr = false;
        int slashIdx = token.IndexOf('/');
        if (slashIdx > 0)
        {
            addrPart = token[..slashIdx];
            string prefixStr = token[(slashIdx + 1)..];
            if (!int.TryParse(prefixStr, out int prefix) || prefix < 0 || prefix > 128)
                return false;
            isCidr = true;
        }

        // Strip brackets: [::1]
        if (addrPart.StartsWith('[') && addrPart.EndsWith(']'))
            addrPart = addrPart[1..^1];

        if (!IPAddress.TryParse(addrPart, out IPAddress? ip))
            return false;

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            return false;

        var addrClass = ClassifyIPv6(ip);

        parsed = new ParsedNetworkAddress
        {
            Value = token,
            AddressClass = addrClass,
            IsCidr = isCidr,
            IsUrl = false,
            IsHostname = false
        };

        return true;
    }

    public static bool TryParseUrlOrHostname(string token, out ParsedNetworkAddress parsed)
    {
        parsed = default;

        // Try as URI
        if (Uri.TryCreate(token, UriKind.Absolute, out Uri? uri))
        {
            if (uri.Scheme is "http" or "https" or "ftp" or "ssh")
            {
                parsed = new ParsedNetworkAddress
                {
                    Value = token,
                    AddressClass = NetworkAddressClass.Public,
                    IsCidr = false,
                    IsUrl = true,
                    IsHostname = false
                };
                return true;
            }
        }

        // Try as hostname:port or plain hostname
        if (IsLikelyHostname(token))
        {
            parsed = new ParsedNetworkAddress
            {
                Value = token,
                AddressClass = NetworkAddressClass.Public,
                IsCidr = false,
                IsUrl = false,
                IsHostname = true
            };
            return true;
        }

        return false;
    }

    public static NetworkAddressClass ClassifyIPv4(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return NetworkAddressClass.Public;

        uint addr = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);

        // Loopback: 127.0.0.0/8
        if ((addr & 0xFF000000) == 0x7F000000)
            return NetworkAddressClass.Loopback;

        // RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if ((addr & 0xFF000000) == 0x0A000000)
            return NetworkAddressClass.Private;
        if ((addr & 0xFFF00000) == 0xAC100000)
            return NetworkAddressClass.Private;
        if ((addr & 0xFFFF0000) == 0xC0A80000)
            return NetworkAddressClass.Private;

        // Link-local: 169.254.0.0/16
        if ((addr & 0xFFFF0000) == 0xA9FE0000)
            return NetworkAddressClass.LinkLocal;

        // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        if (addr == 0xC0000200 || (addr & 0xFFFFFF00) == 0xC0000200)
            return NetworkAddressClass.Documentation;
        if (addr == 0xC6336400 || (addr & 0xFFFFFF00) == 0xC6336400)
            return NetworkAddressClass.Documentation;
        if (addr == 0xCB007100 || (addr & 0xFFFFFF00) == 0xCB007100)
            return NetworkAddressClass.Documentation;

        // Benchmark: 198.18.0.0/15
        if ((addr & 0xFFFE0000) == 0xC6120000)
            return NetworkAddressClass.Benchmark;

        // Multicast: 224.0.0.0/4
        if ((addr & 0xF0000000) == 0xE0000000)
            return NetworkAddressClass.Multicast;

        return NetworkAddressClass.Public;
    }

    public static NetworkAddressClass ClassifyIPv6(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length != 16) return NetworkAddressClass.Public;

        // Loopback: ::1
        if (ip.Equals(IPAddress.IPv6Loopback))
            return NetworkAddressClass.Loopback;

        // Link-local: fe80::/10
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
            return NetworkAddressClass.LinkLocal;

        // Multicast: ff00::/8
        if (bytes[0] == 0xFF)
            return NetworkAddressClass.Multicast;

        // Unique local (RFC 4193): fc00::/7 → fc00::/8 and fd00::/8
        if ((bytes[0] & 0xFE) == 0xFC)
            return NetworkAddressClass.Private;

        // Documentation: 2001:db8::/32
        if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8)
            return NetworkAddressClass.Documentation;

        return NetworkAddressClass.Public;
    }

    private static bool ShouldReport(ParsedNetworkAddress parsed, bool includePrivate, bool includePublic)
    {
        return parsed.AddressClass switch
        {
            NetworkAddressClass.Public => includePublic,
            NetworkAddressClass.Private => includePrivate,
            NetworkAddressClass.Loopback => includePrivate,
            NetworkAddressClass.LinkLocal => includePrivate,
            NetworkAddressClass.Multicast => false,
            NetworkAddressClass.Documentation => false,
            NetworkAddressClass.Benchmark => false,
            _ => false
        };
    }

    private static bool IsLikelyHostname(string token)
    {
        // Must contain at least one dot with valid TLD (2+ alpha chars)
        if (!token.Contains('.')) return false;

        // Check for protocol prefix
        if (token.Contains("://"))
            return false;

        // Port at the end?
        string hostPart = token;
        int colonIdx = token.LastIndexOf(':');
        if (colonIdx > 0)
        {
            string portStr = token[(colonIdx + 1)..];
            if (int.TryParse(portStr, out int port) && port is >= 1 and <= 65535)
                hostPart = token[..colonIdx];
            else
                return false;
        }

        // Validate segments
        foreach (string segment in hostPart.Split('.'))
        {
            if (segment.Length == 0 || segment.Length > 63)
                return false;

            if (!char.IsLetter(segment[0]))
                return false;

            foreach (char c in segment)
            {
                if (!char.IsLetterOrDigit(c) && c != '-')
                    return false;
            }
        }

        return true;
    }

    private static DetectionCandidate CreateCandidate(
        ContentChunk chunk, RuleDefinition rule, DetectorDefinition detector,
        ParsedNetworkAddress parsed, string text, int matchIndex, int matchLength)
    {
        var locator = new SourceLocator.TextLocator(0, matchIndex,
            chunk.SourceStart + matchIndex, matchLength);

        string context = ExtractContext(text, matchIndex, matchLength);

        DetectionConfidence confidence = parsed.AddressClass switch
        {
            NetworkAddressClass.Public => DetectionConfidence.Medium,
            NetworkAddressClass.Private => DetectionConfidence.Low,
            NetworkAddressClass.Loopback => DetectionConfidence.Low,
            _ => DetectionConfidence.Low
        };

        return DetectionCandidate.Create(
            parsed.Value, context, locator,
            rule.Id, detector.Id,
            rule.Severity, confidence, rule.FindingKind, rule.RequiresSemanticReview);
    }

    private static string ExtractContext(string text, int matchIndex, int matchLength)
    {
        int ctxStart = Math.Max(0, matchIndex - 20);
        int ctxEnd = Math.Min(text.Length, matchIndex + matchLength + 20);
        return text[ctxStart..ctxEnd];
    }
}
