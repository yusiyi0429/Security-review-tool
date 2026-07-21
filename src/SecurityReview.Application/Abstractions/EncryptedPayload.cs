namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Versioned AES-256-GCM encrypted envelope. Each field is base64-encoded.
/// </summary>
public sealed record EncryptedPayload(
    int Version,
    string KeyId,
    string NonceBase64,
    string CiphertextBase64,
    string TagBase64);
