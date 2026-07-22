using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityReview.RulePack.Signing;

/// <summary>
/// ECDSA P-256 signer and verifier for rule pack packages.
/// Keys, key paths, and key material are never logged.
/// </summary>
public static class EcdsaRulePackSigner
{
    public const string AlgorithmName = "ECDSA_P256_SHA256_P1363";
    public const string DefaultSignerKeyId = "rules-team-prod-01";

    private static readonly HashSet<string> ExpectedEntries = new(StringComparer.Ordinal)
    {
        "manifest.json",
        "signature.json",
        "categories.json",
        "assets.json",
        "rules.json",
        "detectors.json",
        "compliance.json",
        "dictionaries/entities.json",
        "placeholders.json",
        "licenses.json",
    };

    // ── Key management ────────────────────────────────────────────

    /// <summary>
    /// Loads an ECDsa P-256 private key from a PEM file.
    /// Throws with a stable error message on failure (no path or key material in message).
    /// </summary>
    public static ECDsa LoadPrivateKey(string pemPath)
    {
        ArgumentNullException.ThrowIfNull(pemPath);

        byte[] pemBytes;
        try
        {
            pemBytes = File.ReadAllBytes(pemPath);
        }
        catch (Exception ex) when (ex is not ArgumentNullException)
        {
            throw new InvalidOperationException("Failed to read the private key file.", ex);
        }

        // Try ImportFromPem first
        try
        {
            var key = ECDsa.Create();
            key.ImportFromPem(Encoding.UTF8.GetString(pemBytes));
            return key;
        }
        catch
        {
            // Continue to next format
        }

        // Try ImportECPrivateKey
        try
        {
            var key = ECDsa.Create();
            key.ImportECPrivateKey(pemBytes, out _);
            return key;
        }
        catch
        {
            // Continue to next format
        }

        // Try ImportPkcs8PrivateKey
        try
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pemBytes, out _);
            return key;
        }
        catch
        {
            // All formats failed
        }

        throw new InvalidOperationException("Failed to import the private key in any supported format.");
    }

    /// <summary>
    /// Creates a fresh ECDSA key pair on the NIST P-256 curve (for testing).
    /// </summary>
    public static ECDsa CreateTestKeyPair()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    // ── Signing ───────────────────────────────────────────────────

    /// <summary>
    /// Signs manifest UTF-8 bytes with ECDSA P-256 SHA-256 in IEEE P1363 fixed-field concatenation format.
    /// Returns a 64-byte signature.
    /// </summary>
    public static byte[] SignManifest(byte[] manifestUtf8Bytes, ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(manifestUtf8Bytes);
        ArgumentNullException.ThrowIfNull(privateKey);

        return privateKey.SignData(manifestUtf8Bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Writes the signature.json payload as UTF-8 bytes.
    /// </summary>
    public static byte[] WriteSignatureJson(
        byte[] signature,
        string signerKeyId,
        string? signerPublicKeyBase64 = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(signerKeyId);

        string signatureBase64 = Convert.ToBase64String(signature);

        string json = string.IsNullOrWhiteSpace(signerPublicKeyBase64)
            ? $$"""{"algorithm":"{{AlgorithmName}}","signer_key_id":"{{EscapeJson(signerKeyId)}}","signature_base64":"{{signatureBase64}}"}"""
            : $$"""{"algorithm":"{{AlgorithmName}}","signer_key_id":"{{EscapeJson(signerKeyId)}}","signature_base64":"{{signatureBase64}}","signer_public_key_base64":"{{EscapeJson(signerPublicKeyBase64)}}"}""";

        return Encoding.UTF8.GetBytes(json);
    }

    // ── Verification ──────────────────────────────────────────────

    /// <summary>
    /// Verifies a signed rule pack ZIP. Opens the ZIP, reads manifest.json and signature.json,
    /// checks integrity and signature validity.
    /// </summary>
    public static VerifyResult VerifyPackage(byte[] zipBytes, string expectedSignerKeyId)
    {
        ArgumentNullException.ThrowIfNull(zipBytes);
        ArgumentNullException.ThrowIfNull(expectedSignerKeyId);

        ZipArchive? archive = null;
        try
        {
            var stream = new MemoryStream(zipBytes);
            archive = new ZipArchive(stream, ZipArchiveMode.Read);
        }
        catch
        {
            return new VerifyResult(false, "INVALID_ZIP");
        }

        using (archive)
        {
            if (archive.Entries.Count != ExpectedEntries.Count)
            {
                return new VerifyResult(
                    false,
                    archive.Entries.Count > ExpectedEntries.Count ? "EXTRA_ENTRY" : "INVALID_ZIP");
            }

            var seenEntries = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in archive.Entries)
            {
                string name = entry.FullName.Replace('\\', '/');
                if (!ExpectedEntries.Contains(name) || !seenEntries.Add(name))
                    return new VerifyResult(false, "EXTRA_ENTRY");
            }

            // Read manifest.json
            var manifestEntry = archive.GetEntry("manifest.json");
            if (manifestEntry is null)
            {
                return new VerifyResult(false, "MISSING_MANIFEST");
            }

            byte[] manifestBytes = ReadEntryBytes(manifestEntry);

            // Read signature.json
            var sigEntry = archive.GetEntry("signature.json");
            if (sigEntry is null)
            {
                return new VerifyResult(false, "MISSING_SIGNATURE");
            }

            byte[] sigBytes = ReadEntryBytes(sigEntry);
            var sigData = ParseSignatureJson(sigBytes);

            if (sigData is null)
            {
                return new VerifyResult(false, "MISSING_SIGNATURE");
            }

            if (!string.Equals(sigData.Algorithm, AlgorithmName, StringComparison.Ordinal))
                return new VerifyResult(false, "SIGNATURE_INVALID");

            // Check signer key ID
            if (!string.Equals(sigData.SignerKeyId, expectedSignerKeyId, StringComparison.Ordinal))
            {
                return new VerifyResult(false, "SIGNER_ID_MISMATCH");
            }

            // Verify each file entry in manifest matches ZIP contents
            var manifest = ParseManifestForVerification(manifestBytes);
            if (manifest is null)
            {
                return new VerifyResult(false, "MANIFEST_TAMPERED");
            }

            foreach (var entry in archive.Entries)
            {
                string entryName = entry.FullName.Replace('\\', '/');
                if (entryName is "manifest.json" or "signature.json")
                    continue;

                var expected = manifest.Files
                    .FirstOrDefault(f => string.Equals(f.Path, entryName, StringComparison.Ordinal));

                if (expected is null)
                {
                    return new VerifyResult(false, "EXTRA_ENTRY");
                }

                byte[] entryContent = ReadEntryBytes(entry);
                string actualSha256 = Convert.ToHexStringLower(SHA256.HashData(entryContent));

                if (!string.Equals(actualSha256, expected.Sha256, StringComparison.Ordinal))
                {
                    return new VerifyResult(false, "TAMPERED_ENTRY");
                }
            }

            // Verify signature over manifest.json
            try
            {
                byte[] publicKeyBytes = Convert.FromBase64String(sigData.SignerPublicKeyBase64 ?? "");
                using var publicKey = ImportPublicKeyFromBase64Bytes(publicKeyBytes);

                if (sigData.Signature is null)
                    return new VerifyResult(false, "SIGNATURE_INVALID");

                bool valid = publicKey.VerifyData(manifestBytes, sigData.Signature,
                    HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                if (!valid)
                {
                    return new VerifyResult(false, "SIGNATURE_INVALID");
                }
            }
            catch
            {
                return new VerifyResult(false, "SIGNATURE_INVALID");
            }

            return new VerifyResult(true, "");
        }
    }

    // ── Public key import/export ──────────────────────────────────

    /// <summary>
    /// Exports the public key as a base64-encoded SubjectPublicKeyInfo.
    /// </summary>
    public static string GetPublicKeyBase64(ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        byte[] spki = privateKey.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(spki);
    }

    /// <summary>
    /// Imports an ECDsa public key from a base64-encoded SubjectPublicKeyInfo.
    /// </summary>
    public static ECDsa ImportPublicKeyFromBase64(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        byte[] spki = Convert.FromBase64String(base64);
        return ImportPublicKeyFromBase64Bytes(spki);
    }

    private static ECDsa ImportPublicKeyFromBase64Bytes(byte[] spki)
    {
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return key;
    }

    // ── Helpers ───────────────────────────────────────────────────

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    private sealed record SignatureJsonData
    {
        public string? Algorithm { get; init; }
        public string? SignerKeyId { get; init; }
        public string? SignatureBase64 { get; init; }
        public string? SignerPublicKeyBase64 { get; init; }
        public byte[]? Signature { get; set; }
    }

    private static SignatureJsonData? ParseSignatureJson(byte[] jsonBytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonBytes);
            var root = doc.RootElement;

            var data = new SignatureJsonData
            {
                Algorithm = root.TryGetProperty("algorithm", out var alg) ? alg.GetString() : null,
                SignerKeyId = root.TryGetProperty("signer_key_id", out var kid) ? kid.GetString() : null,
                SignatureBase64 = root.TryGetProperty("signature_base64", out var sig) ? sig.GetString() : null,
                SignerPublicKeyBase64 = root.TryGetProperty("signer_public_key_base64", out var pk) ? pk.GetString() : null,
            };

            if (data.SignatureBase64 is not null)
            {
                data.Signature = Convert.FromBase64String(data.SignatureBase64);
            }

            return data;
        }
        catch
        {
            return null;
        }
    }

    private sealed record ManifestVerificationData
    {
        public IReadOnlyList<ManifestFileEntry> Files { get; init; } = Array.Empty<ManifestFileEntry>();
    }

    private sealed record ManifestFileEntry
    {
        public string Path { get; init; } = "";
        public string Sha256 { get; init; } = "";
        public long Size { get; init; }
    }

    private static ManifestVerificationData? ParseManifestForVerification(byte[] jsonBytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonBytes);
            var root = doc.RootElement;

            var files = new List<ManifestFileEntry>();
            if (root.TryGetProperty("files", out var filesArray) && filesArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var fileElement in filesArray.EnumerateArray())
                {
                    string path = fileElement.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
                    string sha256 = fileElement.TryGetProperty("sha256", out var s) ? s.GetString() ?? "" : "";
                    long size = fileElement.TryGetProperty("size", out var sz) && sz.TryGetInt64(out var v) ? v : 0;

                    files.Add(new ManifestFileEntry { Path = path, Sha256 = sha256, Size = size });
                }
            }

            return new ManifestVerificationData { Files = files };
        }
        catch
        {
            return null;
        }
    }

    private static string EscapeJson(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r")
            .Replace("\t", "\\t");
    }
}
