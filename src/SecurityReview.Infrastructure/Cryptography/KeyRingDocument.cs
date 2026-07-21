using System.Text.Json.Serialization;

namespace SecurityReview.Infrastructure.Cryptography;

/// <summary>
/// JSON document stored in <c>keyring.dat</c> containing scheme version,
/// DPAPI-protected master key (base64), a hex-encoded key ID, and creation
/// timestamp.
/// </summary>
internal sealed class KeyRingDocument
{
    [JsonPropertyName("schema_version")]
    public int schema_version { get; set; }

    [JsonPropertyName("key_id")]
    public string key_id { get; set; } = string.Empty;

    [JsonPropertyName("protected_data_base64")]
    public string protected_data_base64 { get; set; } = string.Empty;

    [JsonPropertyName("created_at_utc")]
    public string created_at_utc { get; set; } = string.Empty;
}

[JsonSerializable(typeof(KeyRingDocument))]
internal sealed partial class KeyRingDocumentJsonContext : JsonSerializerContext;
