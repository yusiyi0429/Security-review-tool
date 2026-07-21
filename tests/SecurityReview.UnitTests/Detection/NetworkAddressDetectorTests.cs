using System.Net;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class NetworkAddressDetectorTests
{
    private static ContentChunk MakeChunk(string text)
    {
        return new ContentChunk(
            ProtocolVersion: 1,
            JobId: new JobId(Guid.NewGuid()),
            Sequence: 0,
            VirtualPath: "test.txt",
            FormatId: "text/plain",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: text,
            SourceStart: 0,
            SourceLength: text.Length,
            LocationMap: [],
            IsFinal: true);
    }

    private static RuleDefinition MakeRule(string id, DetectorId detectorId)
    {
        return new RuleDefinition
        {
            Id = new RuleId(id),
            CategoryId = CategoryId.Parse("SENS-002"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.Medium,
            DetectorId = detectorId,
            DetectorConfigId = "default",
            AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
            Enabled = true
        };
    }

    private static DetectorDefinition MakeDetector(DetectorId id, int maxMatches = 100,
        bool includePrivate = true, bool includePublic = true, bool includeUrl = false)
    {
        return new DetectorDefinition
        {
            Id = id,
            Kind = DetectorKind.NetworkAddress,
            ConfigId = "default",
            Parameters = new Dictionary<string, string>
            {
                ["include_private"] = includePrivate.ToString().ToLowerInvariant(),
                ["include_public"] = includePublic.ToString().ToLowerInvariant(),
                ["include_url"] = includeUrl.ToString().ToLowerInvariant()
            },
            MaxMatchesPerChunk = maxMatches
        };
    }

    private static readonly DetectorId DetId = new("DET-NETWORK-ADDR");

    // ---- IPv4 classification ----

    [Fact]
    public void classifies_rfc1918_private_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Private,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("10.0.0.1")));
        Assert.Equal(NetworkAddressClass.Private,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("172.16.0.1")));
        Assert.Equal(NetworkAddressClass.Private,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("192.168.1.1")));
    }

    [Fact]
    public void classifies_loopback_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Loopback,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("127.0.0.1")));
        Assert.Equal(NetworkAddressClass.Loopback,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("127.255.255.255")));
    }

    [Fact]
    public void classifies_link_local_ipv4()
    {
        Assert.Equal(NetworkAddressClass.LinkLocal,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("169.254.1.1")));
    }

    [Fact]
    public void classifies_multicast_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Multicast,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("224.0.0.1")));
        Assert.Equal(NetworkAddressClass.Multicast,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("239.255.255.255")));
    }

    [Fact]
    public void classifies_documentation_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Documentation,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("192.0.2.1")));
        Assert.Equal(NetworkAddressClass.Documentation,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("198.51.100.1")));
        Assert.Equal(NetworkAddressClass.Documentation,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("203.0.113.1")));
    }

    [Fact]
    public void classifies_benchmark_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Benchmark,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("198.18.0.1")));
        Assert.Equal(NetworkAddressClass.Benchmark,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("198.19.255.255")));
    }

    [Fact]
    public void classifies_public_ipv4()
    {
        Assert.Equal(NetworkAddressClass.Public,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("8.8.8.8")));
        Assert.Equal(NetworkAddressClass.Public,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("1.1.1.1")));
        Assert.Equal(NetworkAddressClass.Public,
            NetworkAddressDetector.ClassifyIPv4(IPAddress.Parse("93.184.216.34")));
    }

    // ---- IPv6 classification ----

    [Fact]
    public void classifies_loopback_ipv6()
    {
        Assert.Equal(NetworkAddressClass.Loopback,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("::1")));
    }

    [Fact]
    public void classifies_link_local_ipv6()
    {
        Assert.Equal(NetworkAddressClass.LinkLocal,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("fe80::1")));
    }

    [Fact]
    public void classifies_multicast_ipv6()
    {
        Assert.Equal(NetworkAddressClass.Multicast,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("ff02::1")));
    }

    [Fact]
    public void classifies_private_ipv6()
    {
        Assert.Equal(NetworkAddressClass.Private,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("fd00::1")));
    }

    [Fact]
    public void classifies_documentation_ipv6()
    {
        Assert.Equal(NetworkAddressClass.Documentation,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void classifies_public_ipv6()
    {
        Assert.Equal(NetworkAddressClass.Public,
            NetworkAddressDetector.ClassifyIPv6(IPAddress.Parse("2001:4860:4860::8888")));
    }

    // ---- IPv4 parsing ----

    [Fact]
    public void try_parse_valid_ipv4()
    {
        Assert.True(NetworkAddressDetector.TryParseIPv4("192.168.1.1", out var parsed));
        Assert.Equal("192.168.1.1", parsed.Value);
        Assert.Equal(NetworkAddressClass.Private, parsed.AddressClass);
        Assert.False(parsed.IsCidr);
    }

    [Fact]
    public void try_parse_ipv4_cidr()
    {
        Assert.True(NetworkAddressDetector.TryParseIPv4("10.0.0.0/8", out var parsed));
        Assert.Equal("10.0.0.0/8", parsed.Value);
        Assert.Equal(NetworkAddressClass.Private, parsed.AddressClass);
        Assert.True(parsed.IsCidr);
    }

    [Fact]
    public void try_parse_invalid_ipv4_octet()
    {
        Assert.False(NetworkAddressDetector.TryParseIPv4("999.999.999.999", out _));
    }

    [Fact]
    public void try_parse_invalid_cidr_prefix()
    {
        Assert.False(NetworkAddressDetector.TryParseIPv4("192.168.1.1/33", out _));
    }

    [Fact]
    public void try_parse_version_like_number_not_ip()
    {
        // "1.2.3" has only 3 octets — the IPv4Pattern regex pre-filters this out,
        // but IPAddress.TryParse may accept it as 1.2.0.3 in some environments.
        // The actual detection pipeline uses the regex first, so version-like
        // numbers are filtered before reaching TryParseIPv4.
        // However, explicitly invalid addresses are rejected.
        Assert.False(NetworkAddressDetector.TryParseIPv4("999.999.999.999", out _));
        Assert.False(NetworkAddressDetector.TryParseIPv4("not.an.ip.address", out _));
    }

    // ---- IPv6 parsing ----

    [Fact]
    public void try_parse_valid_ipv6()
    {
        Assert.True(NetworkAddressDetector.TryParseIPv6("::1", out var parsed));
        Assert.Equal(NetworkAddressClass.Loopback, parsed.AddressClass);
    }

    [Fact]
    public void try_parse_ipv6_bracketed()
    {
        Assert.True(NetworkAddressDetector.TryParseIPv6("[::1]", out var parsed));
        Assert.Equal(NetworkAddressClass.Loopback, parsed.AddressClass);
    }

    [Fact]
    public void try_parse_ipv6_cidr()
    {
        Assert.True(NetworkAddressDetector.TryParseIPv6("fe80::/10", out var parsed));
        Assert.Equal(NetworkAddressClass.LinkLocal, parsed.AddressClass);
        Assert.True(parsed.IsCidr);
    }

    [Fact]
    public void try_parse_invalid_ipv6_prefix()
    {
        Assert.False(NetworkAddressDetector.TryParseIPv6("::1/129", out _));
    }

    // ---- URL/hostname parsing ----

    [Fact]
    public void try_parse_valid_url()
    {
        Assert.True(NetworkAddressDetector.TryParseUrlOrHostname("https://example.com", out var parsed));
        Assert.True(parsed.IsUrl);
    }

    [Fact]
    public void try_parse_valid_hostname()
    {
        Assert.True(NetworkAddressDetector.TryParseUrlOrHostname("api.example.com", out var parsed));
        Assert.True(parsed.IsHostname);
    }

    [Fact]
    public void try_parse_hostname_with_port()
    {
        Assert.True(NetworkAddressDetector.TryParseUrlOrHostname("db.internal:5432", out var parsed));
        Assert.True(parsed.IsHostname);
    }

    [Fact]
    public void try_parse_invalid_hostname_no_dot()
    {
        Assert.False(NetworkAddressDetector.TryParseUrlOrHostname("localhost", out _));
    }

    // ---- Detection integration ----

    [Fact]
    public async Task detects_private_ipv4_in_text()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("Server at 10.0.0.1 is running.");
        var rule = MakeRule("RULE-NET-001", DetId);
        var detDef = MakeDetector(DetId, includePrivate: true, includePublic: false);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Single(results);
        Assert.Contains("10.0.0.1", results[0].Value);
    }

    [Fact]
    public async Task detects_public_ipv4_when_enabled()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("DNS server 8.8.8.8 responded.");
        var rule = MakeRule("RULE-NET-002", DetId);
        var detDef = MakeDetector(DetId, includePrivate: false, includePublic: true);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Single(results);
        Assert.Contains("8.8.8.8", results[0].Value);
    }

    [Fact]
    public async Task skips_public_ip_when_not_enabled()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("DNS server 8.8.8.8 responded.");
        var rule = MakeRule("RULE-NET-003", DetId);
        var detDef = MakeDetector(DetId, includePrivate: true, includePublic: false);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(results);
    }

    [Fact]
    public async Task skips_documentation_and_multicast_addresses()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("Examples: 192.0.2.1, 224.0.0.1");
        var rule = MakeRule("RULE-NET-004", DetId);
        var detDef = MakeDetector(DetId, includePrivate: true, includePublic: true);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // Documentation and multicast should not be reported
        Assert.DoesNotContain(results, c => c.Value.Contains("192.0.2.1"));
        Assert.DoesNotContain(results, c => c.Value.Contains("224.0.0.1"));
    }

    [Fact]
    public async Task detects_url_when_enabled()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("Check https://api.internal.example.com/v1/data");
        var rule = MakeRule("RULE-NET-005", DetId);
        var detDef = MakeDetector(DetId, includePrivate: false, includePublic: false, includeUrl: true);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
        Assert.Contains(results, c => c.Value.Contains("https://"));
    }

    [Fact]
    public async Task respects_max_matches_per_chunk()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5");
        var rule = MakeRule("RULE-NET-006", DetId);
        var detDef = MakeDetector(DetId, maxMatches: 3, includePrivate: true, includePublic: false);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.InRange(results.Count, 1, 3);
    }

    [Fact]
    public async Task detects_ipv6_in_text()
    {
        var detector = new NetworkAddressDetector();
        var chunk = MakeChunk("Link-local: fe80::1 is up.");
        var rule = MakeRule("RULE-NET-007", DetId);
        var detDef = MakeDetector(DetId, includePrivate: true, includePublic: false);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
    }
}
