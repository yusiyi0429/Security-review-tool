using System.Security.Cryptography;
using System.Text;

namespace SecurityReview.Application.Caching;

/// <summary>
/// Stable cache key for the semantic (LLM) review stage. Every component
/// is a fingerprint or configuration identifier — no raw values, context
/// snippets, or API keys enter the key.
/// </summary>
public sealed class SemanticCacheKey
{
    public string CandidateHmac { get; }
    public string MaskedContextSha256 { get; }
    public string EndpointOriginFingerprint { get; }
    public string Model { get; }
    public string ResponseFormatMode { get; }
    public string TemperatureMode { get; }
    public string PromptHash { get; }
    public string RulePackHash { get; }
    public string AdapterVersion { get; }

    /// <summary>Lowercase hex-encoded SHA-256 of the canonical key material.</summary>
    public string Key => _key.Value;
    private readonly Lazy<string> _key;

    public SemanticCacheKey(
        string candidateHmac,
        string maskedContextSha256,
        string endpointOriginFingerprint,
        string model,
        string responseFormatMode,
        string temperatureMode,
        string promptHash,
        string rulePackHash,
        string adapterVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidateHmac);
        ArgumentException.ThrowIfNullOrWhiteSpace(maskedContextSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointOriginFingerprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseFormatMode);
        ArgumentException.ThrowIfNullOrWhiteSpace(temperatureMode);
        ArgumentException.ThrowIfNullOrWhiteSpace(promptHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(adapterVersion);

        CandidateHmac = candidateHmac;
        MaskedContextSha256 = maskedContextSha256;
        EndpointOriginFingerprint = endpointOriginFingerprint;
        Model = model;
        ResponseFormatMode = responseFormatMode;
        TemperatureMode = temperatureMode;
        PromptHash = promptHash;
        RulePackHash = rulePackHash;
        AdapterVersion = adapterVersion;

        _key = new Lazy<string>(ComputeKey, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    private string ComputeKey()
    {
        string canonical = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"semantic|{CandidateHmac}|{MaskedContextSha256}|{EndpointOriginFingerprint}|{Model}|{ResponseFormatMode}|{TemperatureMode}|{PromptHash}|{RulePackHash}|{AdapterVersion}");
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexStringLower(hash);
    }
}
