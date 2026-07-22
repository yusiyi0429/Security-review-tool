using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Signing;

namespace SecurityReview.RulePack.Validation;

/// <summary>
/// Validates a rule pack ZIP byte-for-byte before storage.
/// Validation order: ZIP limits → manifest schema → entry allowlist →
/// size/hash → signer key → ECDSA → client/version → graph/safety → summary.
/// </summary>
public class RulePackageValidator : IRulePackValidator
{
    public const long MaxCompressedSize = 256L * 1024 * 1024; // 256 MiB
    public const long MaxTotalUncompressed = 1L * 1024 * 1024 * 1024; // 1 GiB

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

    public ValidationSummary Validate(byte[] zipBytes, TrustedSignerStore signerStore, string appVersion)
    {
        ArgumentNullException.ThrowIfNull(zipBytes);
        ArgumentNullException.ThrowIfNull(signerStore);
        ArgumentNullException.ThrowIfNull(appVersion);

        // ── Step 1: ZIP limits ───────────────────────────────────────
        if (zipBytes.Length > MaxCompressedSize)
            return Fail("INVALID_ZIP");

        using var stream = new MemoryStream(zipBytes);
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        }
        catch
        {
            return Fail("INVALID_ZIP");
        }

        using (archive)
        {
            // Path traversal check — reject "../" or absolute paths in entry names
            foreach (var entry in archive.Entries)
            {
                string name = NormalizedEntryName(entry);
                if (IsPathTraversal(name))
                    return Fail("INVALID_ZIP");
            }

            // ── Step 2: Manifest schema ───────────────────────────────
            var manifestEntry = archive.GetEntry("manifest.json");
            if (manifestEntry is null)
                return Fail("MANIFEST_TAMPERED");

            byte[] manifestBytes;
            try
            {
                manifestBytes = ReadEntryBytes(manifestEntry);
            }
            catch
            {
                return Fail("MANIFEST_TAMPERED");
            }

            RulePackManifest? manifest;
            try
            {
                manifest = JsonSerializer.Deserialize<RulePackManifest>(manifestBytes);
            }
            catch (JsonException)
            {
                return Fail("MANIFEST_TAMPERED");
            }

            if (manifest is null)
                return Fail("MANIFEST_TAMPERED");

            if (manifest.SchemaVersion != 1)
                return Fail("SCHEMA_INVALID");

            // ── Step 3: Exact entry allowlist ─────────────────────────
            if (archive.Entries.Count != ExpectedEntries.Count)
                return Fail("EXTRA_ENTRY");

            foreach (var entry in archive.Entries)
            {
                string name = NormalizedEntryName(entry);
                if (!ExpectedEntries.Contains(name))
                    return Fail("EXTRA_ENTRY");
            }

            // ── Step 4: Size/hash ─────────────────────────────────────
            var manifestFileMap = new Dictionary<string, RulePackManifest.FileEntry>(StringComparer.Ordinal);
            long totalDeclaredSize = 0;
            foreach (var file in manifest.Files)
            {
                manifestFileMap[file.Path] = file;
                totalDeclaredSize += file.Size;
            }

            if (totalDeclaredSize > MaxTotalUncompressed)
                return Fail("SIZE_MISMATCH");

            foreach (var entry in archive.Entries)
            {
                string name = NormalizedEntryName(entry);

                if (name is "manifest.json" or "signature.json")
                    continue;

                if (!manifestFileMap.TryGetValue(name, out var declared))
                    return Fail("EXTRA_ENTRY");

                byte[] content = ReadEntryBytes(entry);

                if (content.Length != declared.Size)
                    return Fail("SIZE_MISMATCH");

                string actualHash = Convert.ToHexStringLower(SHA256.HashData(content));
                if (!string.Equals(actualHash, declared.Sha256, StringComparison.Ordinal))
                    return Fail("HASH_MISMATCH");
            }

            // ── Step 5: Signer key allowlist ──────────────────────────
            if (!signerStore.IsSignerTrusted(manifest.SignerKeyId))
                return Fail("SIGNER_NOT_TRUSTED");

            // ── Step 6: ECDSA signature ───────────────────────────────
            var verifyResult = EcdsaRulePackSigner.VerifyPackage(zipBytes, manifest.SignerKeyId);
            if (!verifyResult.IsValid)
                return Fail(verifyResult.ErrorCode);

            // Additional verification with the trusted public key
            using var trustedKey = signerStore.TryGetPublicKey(manifest.SignerKeyId);
            if (trustedKey is null)
                return Fail("SIGNER_NOT_TRUSTED");

            var sigEntry = archive.GetEntry("signature.json");
            Debug.Assert(sigEntry is not null, "signature.json must exist after VerifyPackage passed.");

            byte[] sigBytes = ReadEntryBytes(sigEntry!);
            byte[]? signature = ParseSignature(sigBytes);
            if (signature is null)
                return Fail("SIGNATURE_INVALID");

            try
            {
                bool valid = trustedKey.VerifyData(
                    manifestBytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                if (!valid)
                    return Fail("SIGNATURE_INVALID");
            }
            catch
            {
                return Fail("SIGNATURE_INVALID");
            }

            // ── Step 7: Client/version ────────────────────────────────
            if (!Version.TryParse(manifest.MinClientVersion, out var minVersion))
                return Fail("CLIENT_TOO_OLD");

            if (!Version.TryParse(appVersion, out var appVer))
                return Fail("CLIENT_TOO_OLD");

            if (minVersion > appVer)
                return Fail("CLIENT_TOO_OLD");

            // ── Step 8: Graph/safety ──────────────────────────────────
            RulePackDocument document;
            try
            {
                document = LoadDocument(archive);
            }
            catch (JsonException)
            {
                return Fail("GRAPH_INVALID");
            }
            catch (InvalidOperationException)
            {
                return Fail("GRAPH_INVALID");
            }

            var graphResult = RuleGraphValidator.Validate(document);
            if (!graphResult.IsValid)
                return Fail("GRAPH_INVALID");

            // ── Step 9: Summary ───────────────────────────────────────
            string packageSha256 = Convert.ToHexStringLower(SHA256.HashData(zipBytes));

            return new ValidationSummary
            {
                IsValid = true,
                Manifest = manifest,
                Document = document,
                PackageSha256 = packageSha256,
            };
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private static ValidationSummary Fail(string errorCode) => new()
    {
        IsValid = false,
        ErrorCode = errorCode,
    };

    private static string NormalizedEntryName(ZipArchiveEntry entry) =>
        entry.FullName.Replace('\\', '/');

    /// <summary>
    /// Rejects "../" or absolute paths (leading "/" or Windows "C:").
    /// </summary>
    private static bool IsPathTraversal(string name)
    {
        if (name.StartsWith('/'))
            return true;

        if (name.Length >= 2 && char.IsAsciiLetter(name[0]) && name[1] == ':')
            return true;

        if (name.Contains("../"))
            return true;

        return false;
    }

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var entryStream = entry.Open();
        using var ms = new MemoryStream();
        entryStream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Parses the signature_base64 field from signature.json.
    /// Returns <c>null</c> on any parse error.
    /// </summary>
    private static byte[]? ParseSignature(byte[] sigJsonBytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(sigJsonBytes);
            var root = doc.RootElement;

            if (!root.TryGetProperty("signature_base64", out var sigProp))
                return null;

            string? base64 = sigProp.GetString();
            if (string.IsNullOrWhiteSpace(base64))
                return null;

            return Convert.FromBase64String(base64);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Reads and deserializes each document file from the ZIP and assembles a
    /// <see cref="RulePackDocument"/>.
    /// </summary>
    private static RulePackDocument LoadDocument(ZipArchive archive)
    {
        var categories = ReadAndDeserialize<IReadOnlyList<CategoryDefinition>>(
            archive, "categories.json",
            RulePackJsonContext.Default.IReadOnlyListCategoryDefinition);

        var assets = ReadAndDeserialize<IReadOnlyList<AssetPolicy>>(
            archive, "assets.json",
            RulePackJsonContext.Default.IReadOnlyListAssetPolicy);

        var detectors = ReadAndDeserialize<IReadOnlyList<DetectorDefinition>>(
            archive, "detectors.json",
            RulePackJsonContext.Default.IReadOnlyListDetectorDefinition);

        var complianceRules = ReadAndDeserialize<IReadOnlyList<ComplianceRule>>(
            archive, "compliance.json",
            RulePackJsonContext.Default.IReadOnlyListComplianceRule);

        return new RulePackDocument
        {
            Categories = categories,
            Assets = assets,
            Detectors = detectors,
            ComplianceRules = complianceRules,
        };
    }

    private static T ReadAndDeserialize<T>(ZipArchive archive, string entryName,
        JsonTypeInfo<T> typeInfo) where T : class
    {
        var entry = archive.GetEntry(entryName);
        Debug.Assert(entry is not null,
            $"Entry '{entryName}' must exist — entry allowlist already verified.");

        byte[] bytes = ReadEntryBytes(entry!);
        return JsonSerializer.Deserialize(bytes, typeInfo)
            ?? throw new InvalidOperationException($"Deserialization of '{entryName}' returned null.");
    }
}
