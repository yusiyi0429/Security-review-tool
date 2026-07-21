namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Protects and unprotects payloads for database column-level encryption
/// using AES-256-GCM with table/record/field AAD binding.
/// </summary>
public interface IPayloadProtector
{
    EncryptedPayload Protect(string table, string recordId, string fieldName, byte[] plaintext);
    byte[] Unprotect(string table, string recordId, string fieldName, EncryptedPayload payload);
}
