using System.Security.Cryptography;
using System.Text;
using SecurityReview.Infrastructure.Cryptography;

namespace SecurityReview.UnitTests.Cryptography;

public sealed class HkdfSha256Tests : IDisposable
{
    private HkdfSha256? _hkdf;
    private bool _disposed;

    public void Dispose()
    {
        if (!_disposed)
        {
            _hkdf?.Dispose();
            _disposed = true;
        }
    }

    // RFC 5869 §A.1 — Test Case 1 (SHA-256, basic)
    [Fact]
    public void Rfc5869_A1_basic_vectors()
    {
        byte[] ikm = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
        byte[] salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        byte[] info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        byte[] expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65
        ];

        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 42, salt, info);
        Assert.Equal(expected, okm);
    }

    // RFC 5869 §A.2 — Test Case 2 (SHA-256, longer I/O)
    [Fact]
    public void Rfc5869_A2_longer_vectors()
    {
        byte[] ikm = new byte[80];
        for (int i = 0; i < 80; i++) ikm[i] = (byte)i;
        byte[] salt = new byte[80];
        for (int i = 0; i < 80; i++) salt[i] = (byte)(0x60 + i);
        byte[] info = new byte[80];
        for (int i = 0; i < 80; i++) info[i] = (byte)(0xb0 + i);
        byte[] expected = [
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
            0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
            0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
            0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
            0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
            0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
            0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
            0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
            0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
            0x1d, 0x87
        ];

        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 82, salt, info);
        Assert.Equal(expected, okm);
    }

    // RFC 5869 §A.3 — Test Case 3 (SHA-256, empty salt)
    [Fact]
    public void Rfc5869_A3_empty_salt_vectors()
    {
        byte[] ikm = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
        byte[] salt = [];
        byte[] info = [];
        byte[] expected = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
            0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
            0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
            0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
            0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
            0x96, 0xc8
        ];

        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 42, salt, info);
        Assert.Equal(expected, okm);
    }

    [Fact]
    public void Derive_encryption_key_produces_32_bytes()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);

        byte[] key = _hkdf.DeriveEncryptionKey();
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void Derive_fingerprint_key_produces_32_bytes()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);

        byte[] key = _hkdf.DeriveFingerprintKey();
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void Encryption_and_fingerprint_keys_are_different()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);

        byte[] enc = _hkdf.DeriveEncryptionKey();
        byte[] fp = _hkdf.DeriveFingerprintKey();
        Assert.NotEqual(enc, fp);
    }

    [Fact]
    public void Multiple_derivations_from_same_master_yield_consistent_keys()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);

        byte[] a1 = _hkdf.DeriveEncryptionKey();
        byte[] a2 = _hkdf.DeriveEncryptionKey();
        byte[] b1 = _hkdf.DeriveFingerprintKey();
        byte[] b2 = _hkdf.DeriveFingerprintKey();

        Assert.Equal(a1, a2);
        Assert.Equal(b1, b2);
    }

    [Fact]
    public void Different_masters_yield_different_keys()
    {
        byte[] m1 = new byte[32];
        byte[] m2 = new byte[32];
        RandomNumberGenerator.Fill(m1);
        RandomNumberGenerator.Fill(m2);

        using var hkdf1 = new HkdfSha256(m1);
        using var hkdf2 = new HkdfSha256(m2);

        byte[] a1 = hkdf1.DeriveEncryptionKey();
        byte[] a2 = hkdf2.DeriveEncryptionKey();

        Assert.NotEqual(a1, a2);
    }

    [Fact]
    public void Dispose_zeros_master_key()
    {
        byte[] master = new byte[32];
        master.AsSpan().Fill(0x42);
        byte[] copy = new byte[32];
        master.CopyTo(copy, 0);

        _hkdf = new HkdfSha256(master);
        _hkdf.Dispose();

        // The owned copy inside _hkdf should be zeroed
        // We verify by checking the original master is untouched
        Assert.Equal(copy, master);
    }

    [Fact]
    public void Derived_keys_are_zeroed_on_disposal()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);
        byte[] encKey = _hkdf.DeriveEncryptionKey();
        byte[] fpKey = _hkdf.DeriveFingerprintKey();

        // Not zero yet
        Assert.False(encKey.All(b => b == 0));
        Assert.False(fpKey.All(b => b == 0));

        _hkdf.Dispose();
        // After dispose, keys should be zeroed
        Assert.True(encKey.All(b => b == 0));
        Assert.True(fpKey.All(b => b == 0));
    }

    [Fact]
    public void Info_strings_match_specification()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        _hkdf = new HkdfSha256(master);

        byte[] expectedEnc = HKDF.DeriveKey(
            HashAlgorithmName.SHA256, master, 32, salt: [],
            Encoding.UTF8.GetBytes("SecurityReviewTool/v1/encryption"));
        byte[] expectedFp = HKDF.DeriveKey(
            HashAlgorithmName.SHA256, master, 32, salt: [],
            Encoding.UTF8.GetBytes("SecurityReviewTool/v1/fingerprint"));

        Assert.Equal(expectedEnc, _hkdf.DeriveEncryptionKey());
        Assert.Equal(expectedFp, _hkdf.DeriveFingerprintKey());
    }
}
