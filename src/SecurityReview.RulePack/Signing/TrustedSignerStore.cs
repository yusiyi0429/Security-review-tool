using System.Security.Cryptography;
using System.Text.Json;

namespace SecurityReview.RulePack.Signing;

/// <summary>
/// Loads trusted signer public keys from a JSON configuration and validates its release hash.
/// Only public key material is embedded; no private keys.
/// </summary>
public sealed class TrustedSignerStore
{
    private readonly IReadOnlyList<TrustedSigner> _signers;

    public TrustedSignerStore(IReadOnlyList<TrustedSigner> signers)
    {
        ArgumentNullException.ThrowIfNull(signers);
        _signers = signers;
    }

    /// <summary>
    /// Loads the store from a JSON string.
    /// </summary>
    public static TrustedSignerStore Load(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var signers = new List<TrustedSigner>();
        if (root.TryGetProperty("signers", out var signersArray)
            && signersArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in signersArray.EnumerateArray())
            {
                string keyId = s.TryGetProperty("signer_key_id", out var kid)
                    ? kid.GetString() ?? "" : "";
                string base64 = s.TryGetProperty("public_key_base64", out var pk)
                    ? pk.GetString() ?? "" : "";
                string pem = s.TryGetProperty("public_key_pem", out var pp)
                    ? pp.GetString() ?? "" : "";

                signers.Add(new TrustedSigner(keyId, base64, pem));
            }
        }

        return new TrustedSignerStore(signers);
    }

    /// <summary>
    /// Validates the JSON release hash at startup. Returns true if the
    /// SHA-256 of the JSON bytes matches <paramref name="expectedSha256"/>.
    /// </summary>
    public static bool ValidateReleaseHash(string json, string expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(expectedSha256))
            return true; // No hash configured — skip check

        byte[] jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);
        string actual = Convert.ToHexStringLower(SHA256.HashData(jsonBytes));
        return string.Equals(actual, expectedSha256, StringComparison.Ordinal);
    }

    /// <summary>
    /// Returns the <see cref="ECDsa"/> public key for the given signer key ID,
    /// or <c>null</c> if not found or import fails.
    /// </summary>
    public ECDsa? TryGetPublicKey(string keyId)
    {
        var signer = _signers.FirstOrDefault(
            s => string.Equals(s.SignerKeyId, keyId, StringComparison.Ordinal));

        if (signer is null)
            return null;

        // Try base64 SPKI first, then PEM
        if (!string.IsNullOrWhiteSpace(signer.PublicKeyBase64))
        {
            try
            {
                return EcdsaRulePackSigner.ImportPublicKeyFromBase64(signer.PublicKeyBase64);
            }
            catch
            {
                // Fall through to PEM
            }
        }

        if (!string.IsNullOrWhiteSpace(signer.PublicKeyPem))
        {
            try
            {
                var key = ECDsa.Create();
                key.ImportFromPem(signer.PublicKeyPem);
                return key;
            }
            catch
            {
                // Import failed
            }
        }

        return null;
    }

    /// <summary>
    /// Returns <c>true</c> only when a signer with the given key ID has usable
    /// public-key material in the trusted set.
    /// </summary>
    public bool IsSignerTrusted(string keyId)
    {
        using ECDsa? key = TryGetPublicKey(keyId);
        return key is not null;
    }
}

/// <summary>
/// A single trusted signer entry from <c>trusted-signers.json</c>.
/// </summary>
public sealed record TrustedSigner(
    string SignerKeyId,
    string PublicKeyBase64,
    string PublicKeyPem);
