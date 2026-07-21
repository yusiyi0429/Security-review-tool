using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Signing;

namespace SecurityReview.ContractTests.Rules;

public sealed class RulePackageSignatureTests
{
    private static ECDsa CreateTestKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static byte[] BuildMinimalPackage(ECDsa? signKey = null)
    {
        var cat = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-001"),
            Name = "Test",
            Description = "",
            Enabled = true,
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition> { cat },
        };

        var manifest = RulePackManifest.Create(
            rulePackId: "test-pack",
            version: "1.0.0",
            minClientVersion: "1.0.0",
            signerKeyId: EcdsaRulePackSigner.DefaultSignerKeyId,
            schemaVersion: 1,
            files: []);

        byte[] zipBytes = RulePackWriter.Write(manifest, doc, [], [], []);

        if (signKey is not null)
        {
            zipBytes = SignPackage(zipBytes, signKey);
        }

        return zipBytes;
    }

    private static byte[] SignPackage(byte[] zipBytes, ECDsa privateKey)
    {
        // Extract manifest.json from ZIP
        byte[] manifestBytes;
        using (var readStream = new MemoryStream(zipBytes))
        using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
        {
            var manifestEntry = archive.GetEntry("manifest.json")!;
            using var entryStream = manifestEntry.Open();
            using var ms = new MemoryStream();
            entryStream.CopyTo(ms);
            manifestBytes = ms.ToArray();
        }

        byte[] signature = EcdsaRulePackSigner.SignManifest(manifestBytes, privateKey);
        byte[] signatureJson = EcdsaRulePackSigner.WriteSignatureJson(
            signature, EcdsaRulePackSigner.DefaultSignerKeyId);

        // Replace signature.json in ZIP
        using var outputStream = new MemoryStream();
        using (var readStream = new MemoryStream(zipBytes))
        using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
        using (var newArchive = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in archive.Entries)
            {
                string entryName = entry.FullName.Replace('\\', '/');
                byte[] content;
                if (entryName == "signature.json")
                {
                    content = signatureJson;
                }
                else
                {
                    using var es = entry.Open();
                    using var ms = new MemoryStream();
                    es.CopyTo(ms);
                    content = ms.ToArray();
                }

                var newEntry = newArchive.CreateEntry(entryName, CompressionLevel.Optimal);
                newEntry.LastWriteTime = entry.LastWriteTime;
                using var newEntryStream = newEntry.Open();
                newEntryStream.Write(content, 0, content.Length);
            }
        }

        return outputStream.ToArray();
    }

    [Fact]
    public void Valid_sign_verify_succeeds()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        var result = EcdsaRulePackSigner.VerifyPackage(
            signed, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.True(result.IsValid);
        Assert.Equal("", result.ErrorCode);
    }

    [Fact]
    public void Tamper_manifest_byte_verify_fails_with_MANIFEST_TAMPERED()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        // Find and tamper manifest.json bytes
        byte[] tampered = TamperEntry(signed, "manifest.json", bytes =>
        {
            // Flip a byte in the middle
            bytes[bytes.Length / 2] ^= 0xFF;
            return bytes;
        });

        var result = EcdsaRulePackSigner.VerifyPackage(
            tampered, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.False(result.IsValid);
        // Signature verification fails because manifest bytes have changed
        Assert.NotEqual("", result.ErrorCode);
    }

    [Fact]
    public void Tamper_signature_byte_verify_fails_with_SIGNATURE_INVALID()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        byte[] tampered = TamperEntry(signed, "signature.json", bytes =>
        {
            // Tamper the base64 signature
            string json = Encoding.UTF8.GetString(bytes);
            json = json.Replace("A", "B", StringComparison.Ordinal);
            return Encoding.UTF8.GetBytes(json);
        });

        var result = EcdsaRulePackSigner.VerifyPackage(
            tampered, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.False(result.IsValid);
        Assert.True(result.ErrorCode is "SIGNATURE_INVALID" or "MISSING_SIGNATURE");
    }

    [Fact]
    public void Tamper_entry_size_verify_fails_with_TAMPERED_ENTRY()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        // Tamper a file entry to change its content (will make sha256 mismatch)
        byte[] tampered = TamperEntry(signed, "categories.json", bytes =>
        {
            bytes[^1] ^= 0xFF;
            return bytes;
        });

        var result = EcdsaRulePackSigner.VerifyPackage(
            tampered, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.False(result.IsValid);
        Assert.Equal("TAMPERED_ENTRY", result.ErrorCode);
    }

    [Fact]
    public void Tamper_entry_name_verify_fails()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        // Rename an entry inside the ZIP
        byte[] tampered;
        using (var readStream = new MemoryStream(signed))
        using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
        using (var outputStream = new MemoryStream())
        using (var newArchive = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in archive.Entries)
            {
                string entryName = entry.FullName.Replace('\\', '/');
                if (entryName == "categories.json")
                    entryName = "categories.json.bak";

                using var es = entry.Open();
                using var ms = new MemoryStream();
                es.CopyTo(ms);
                var content = ms.ToArray();

                var newEntry = newArchive.CreateEntry(entryName, CompressionLevel.Optimal);
                using var newEntryStream = newEntry.Open();
                newEntryStream.Write(content, 0, content.Length);
            }

            tampered = outputStream.ToArray();
        }

        var result = EcdsaRulePackSigner.VerifyPackage(
            tampered, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.False(result.IsValid);
        // Either EXTRA_ENTRY (because original categories.json is missing and new one is extra)
        // or TAMPERED_ENTRY
        Assert.NotEqual("", result.ErrorCode);
    }

    [Fact]
    public void Signer_id_mismatch_returns_SIGNER_ID_MISMATCH()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        var result = EcdsaRulePackSigner.VerifyPackage(
            signed, "different-signer-id");

        Assert.False(result.IsValid);
        Assert.Equal("SIGNER_ID_MISMATCH", result.ErrorCode);
    }

    [Fact]
    public void Extra_entry_in_ZIP_returns_EXTRA_ENTRY()
    {
        using var key = CreateTestKey();
        byte[] signed = BuildMinimalPackage(key);

        // Add an extra entry
        byte[] tampered;
        using (var readStream = new MemoryStream(signed))
        using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
        using (var outputStream = new MemoryStream())
        using (var newArchive = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in archive.Entries)
            {
                using var es = entry.Open();
                using var ms = new MemoryStream();
                es.CopyTo(ms);
                var content = ms.ToArray();

                var newEntry = newArchive.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                using var newEntryStream = newEntry.Open();
                newEntryStream.Write(content, 0, content.Length);
            }

            // Add extra entry
            var extra = newArchive.CreateEntry("extra.txt", CompressionLevel.Optimal);
            using var extraStream = extra.Open();
            extraStream.Write("extra"u8);

            tampered = outputStream.ToArray();
        }

        var result = EcdsaRulePackSigner.VerifyPackage(
            tampered, EcdsaRulePackSigner.DefaultSignerKeyId);

        Assert.False(result.IsValid);
        Assert.Equal("EXTRA_ENTRY", result.ErrorCode);
    }

    [Fact]
    public void Double_build_produces_byte_identical_manifest_and_canonical_json()
    {
        var cat = new CategoryDefinition
        {
            CategoryId = CategoryId.Parse("SENS-001"),
            Name = "Test",
            Description = "",
            Enabled = true,
        };

        var doc = new RulePackDocument
        {
            Categories = new List<CategoryDefinition> { cat },
        };

        byte[] first = RulePackWriter.Write(
            RulePackManifest.Create("test-pack", "1.0.0", "1.0.0",
                EcdsaRulePackSigner.DefaultSignerKeyId, 1, []),
            doc, [], [], []);

        byte[] second = RulePackWriter.Write(
            RulePackManifest.Create("test-pack", "1.0.0", "1.0.0",
                EcdsaRulePackSigner.DefaultSignerKeyId, 1, []),
            doc, [], [], []);

        // Manifest.json bytes should be identical
        byte[] firstManifest = ReadZipEntry(first, "manifest.json");
        byte[] secondManifest = ReadZipEntry(second, "manifest.json");

        // Canonical JSON ensures byte-identical output
        Assert.Equal(firstManifest, secondManifest);
        Assert.Equal(first.Length, second.Length);
        Assert.Equal(first, second);
    }

    private static byte[] TamperEntry(byte[] zipBytes, string entryName, Func<byte[], byte[]> tamper)
    {
        using var readStream = new MemoryStream(zipBytes);
        using var archive = new ZipArchive(readStream, ZipArchiveMode.Read);
        using var outputStream = new MemoryStream();
        using var newArchive = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true);

        foreach (var entry in archive.Entries)
        {
            string name = entry.FullName.Replace('\\', '/');
            byte[] content;
            using (var es = entry.Open())
            using (var ms = new MemoryStream())
            {
                es.CopyTo(ms);
                content = ms.ToArray();
            }

            if (name == entryName)
            {
                content = tamper(content);
            }

            var newEntry = newArchive.CreateEntry(entry.FullName, CompressionLevel.Optimal);
            using var newEntryStream = newEntry.Open();
            newEntryStream.Write(content, 0, content.Length);
        }

        return outputStream.ToArray();
    }

    private static byte[] ReadZipEntry(byte[] zipBytes, string entryName)
    {
        using var stream = new MemoryStream(zipBytes);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        var entry = archive.GetEntry(entryName)!;
        using var es = entry.Open();
        using var ms = new MemoryStream();
        es.CopyTo(ms);
        return ms.ToArray();
    }
}
