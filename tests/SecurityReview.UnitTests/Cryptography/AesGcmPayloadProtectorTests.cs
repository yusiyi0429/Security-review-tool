using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Infrastructure.Cryptography;

namespace SecurityReview.UnitTests.Cryptography;

public sealed class AesGcmPayloadProtectorTests : IDisposable
{
    private readonly byte[] _key;
    private readonly string _keyId;
    private readonly AesGcmPayloadProtector _protector;

    public AesGcmPayloadProtectorTests()
    {
        _key = new byte[32];
        _keyId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        RandomNumberGenerator.Fill(_key);
        _protector = new AesGcmPayloadProtector(_key, _keyId);
    }

    public void Dispose()
    {
        _protector.Dispose();
    }

    [Fact]
    public void Same_plaintext_has_different_ciphertext_and_round_trips()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload first = _protector.Protect("finding_occurrences", "id-1", "payload", plaintext);
        EncryptedPayload second = _protector.Protect("finding_occurrences", "id-1", "payload", plaintext);
        Assert.NotEqual(first.NonceBase64, second.NonceBase64);
        Assert.NotEqual(first.CiphertextBase64, second.CiphertextBase64);
        Assert.Equal(plaintext, _protector.Unprotect("finding_occurrences", "id-1", "payload", first));
    }

    [Fact]
    public void Roundtrip_various_sizes()
    {
        foreach (int size in new[] { 0, 1, 16, 256, 1024, 1024 * 1024, 4 * 1024 * 1024 })
        {
            byte[] plaintext = new byte[size];
            RandomNumberGenerator.Fill(plaintext);
            EncryptedPayload payload = _protector.Protect("table", "rec", "field", plaintext);
            byte[] decrypted = _protector.Unprotect("table", "rec", "field", payload);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void Wrong_record_id_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t", "b", "f", payload));
    }

    [Fact]
    public void Wrong_table_name_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t2", "a", "f", payload));
    }

    [Fact]
    public void Wrong_field_name_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t", "a", "f2", payload));
    }

    [Fact]
    public void Mutated_tag_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        EncryptedPayload mutated = payload with { TagBase64 = Convert.ToBase64String(new byte[16]) };
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t", "a", "f", mutated));
    }

    [Fact]
    public void Mutated_ciphertext_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        byte[] ct = Convert.FromBase64String(payload.CiphertextBase64);
        ct[0] ^= 1;
        EncryptedPayload mutated = payload with { CiphertextBase64 = Convert.ToBase64String(ct) };
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t", "a", "f", mutated));
    }

    [Fact]
    public void Wrong_nonce_is_rejected()
    {
        byte[] plaintext = "SYNTHETIC_CANARY"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        byte[] wrongNonce = new byte[12];
        RandomNumberGenerator.Fill(wrongNonce);
        EncryptedPayload mutated = payload with { NonceBase64 = Convert.ToBase64String(wrongNonce) };
        Assert.Throws<AuthenticationTagMismatchException>(() => _protector.Unprotect("t", "a", "f", mutated));
    }

    [Fact]
    public void Payload_version_is_set_to_1()
    {
        byte[] plaintext = "test"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        Assert.Equal(1, payload.Version);
    }

    [Fact]
    public void Payload_contains_key_id()
    {
        byte[] plaintext = "test"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        Assert.Equal(_keyId, payload.KeyId);
    }

    [Fact]
    public void Nonce_is_12_bytes_base64()
    {
        byte[] plaintext = "test"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        byte[] nonce = Convert.FromBase64String(payload.NonceBase64);
        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    public void Tag_is_16_bytes_base64()
    {
        byte[] plaintext = "test"u8.ToArray();
        EncryptedPayload payload = _protector.Protect("t", "a", "f", plaintext);
        byte[] tag = Convert.FromBase64String(payload.TagBase64);
        Assert.Equal(16, tag.Length);
    }

    [Fact]
    public void Plaintext_exceeding_16_mib_is_rejected()
    {
        byte[] largeData = new byte[16 * 1024 * 1024 + 1];
        Assert.Throws<ArgumentException>(() =>
            _protector.Protect("t", "a", "f", largeData));
    }

    [Fact]
    public void Plaintext_at_16_mib_boundary_is_accepted()
    {
        byte[] largeData = new byte[16 * 1024 * 1024];
        RandomNumberGenerator.Fill(largeData);
        EncryptedPayload payload = _protector.Protect("t", "a", "f", largeData);
        byte[] decrypted = _protector.Unprotect("t", "a", "f", payload);
        Assert.Equal(largeData, decrypted);
    }

    [Fact]
    public void Dispose_zeros_key_material()
    {
        byte[] key = new byte[32];
        key.AsSpan().Fill(0x42);
        byte[] copy = new byte[32];
        key.CopyTo(copy, 0);

        var protector = new AesGcmPayloadProtector(key, "test-id");
        protector.Dispose();

        // The protector copies the key; the original buffer is untouched
        Assert.Equal(copy, key);
    }
}
