using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using SecurityReview.Application.Rules;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Rules;
using SecurityReview.Infrastructure.Rules;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Policy;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Signing;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.IntegrationTests.Rules;

/// <summary>
/// Integration tests for the full rule pack import pipeline:
/// validation, downgrade/duplicate guards, atomic store, and active-pointer switch.
///
/// Known limitation: The manifest includes signature.json's hash, and the signature
/// signs the manifest. These two constraints form a circular dependency. The
/// CreateValidPackage helper resolves this by iterating the sign-hash-manifest loop
/// until the manifest bytes converge (the sig.json body is fixed-length across
/// iterations, allowing the fixed-point to be reached in practice).
/// </summary>
public sealed class RulePackImportTests
{
    private const string TestAppVersion = "1.0.0";
    private const string TestSignerKeyId = "test-key";
    private const string TestRulePackId = "test-pack";
    private const string TestVersion1 = "1.0.0";
    private const string TestVersion2 = "2.0.0";

    // ----------------------------------------------------------------- Helpers

    /// <summary>
    /// Creates a minimal baseline <see cref="RulePackDocument"/> with
    /// one category, one asset, one detector, and one compliance rule.
    /// </summary>
    private static RulePackDocument CreateMinimalBaseline()
    {
        return new RulePackDocument
        {
            SchemaVersion = 1,
            Categories = new List<CategoryDefinition>
            {
                new()
                {
                    CategoryId = CategoryId.Parse("SENS-001"),
                    Name = "Sensitive Data Leak",
                    Description = "Detects exposure of sensitive data patterns.",
                    Enabled = true,
                },
            },
            Assets = new List<AssetPolicy>
            {
                new()
                {
                    AssetTypeId = AssetTypeId.Parse("ASSET-001"),
                    Name = "Source Code",
                    Description = "Source code files.",
                    FocusWeights = new Dictionary<CategoryId, double>
                    {
                        [CategoryId.Parse("SENS-001")] = 1.0,
                    },
                    ComplianceRules = new List<ComplianceRule>
                    {
                        new()
                        {
                            Id = "CR-001",
                            AssetTypeId = AssetTypeId.Parse("ASSET-001"),
                            Name = "No secrets in source",
                            Description = "Ensure no secrets are committed.",
                            EvidenceField = "secrets_check",
                            RequiredStatus = "PASS",
                        },
                    },
                },
            },
            Detectors = new List<DetectorDefinition>
            {
                new()
                {
                    Id = new DetectorId("DET-REGEX-001"),
                    Kind = DetectorKind.Dictionary,
                    ConfigId = "sensitive-keywords",
                    Parameters = new Dictionary<string, string>
                    {
                        ["patterns"] = "password,secret,api_key",
                    },
                    MaxMatchesPerChunk = 100,
                },
            },
            ComplianceRules = new List<ComplianceRule>
            {
                new()
                {
                    Id = "CR-001",
                    AssetTypeId = AssetTypeId.Parse("ASSET-001"),
                    Name = "No secrets in source",
                    Description = "Ensure no secrets are committed.",
                    EvidenceField = "secrets_check",
                    RequiredStatus = "PASS",
                },
            },
        };
    }

    /// <summary>
    /// Creates a signed rule pack ZIP.
    ///
    /// In the current design the manifest includes the SHA-256 of every file in
    /// the ZIP (including signature.json) and the signature.json signs the
    /// manifest bytes. Because these two constraints are circular, we iterate
    /// the sign→hash→manifest loop until the manifest bytes stabilise (fixed
    /// point). Since signature.json has a fixed length (the signature is always
    /// 64 bytes → 88 base64 chars), the loop converges when the same manifest
    /// bytes are produced in two consecutive iterations.
    /// </summary>
    private static (byte[] ZipBytes, string Sha256) CreateValidPackage(
        RulePackDocument document,
        string rulePackId,
        string version,
        string minClientVersion,
        string signerKeyId,
        ECDsa privateKey)
    {
        // Serialize the seven content files once — they never change.
        byte[] categoriesBytes = SerializeWithContext(document.Categories,
            RulePackJsonContext.Default.IReadOnlyListCategoryDefinition);
        byte[] assetsBytes = SerializeWithContext(document.Assets,
            RulePackJsonContext.Default.IReadOnlyListAssetPolicy);
        byte[] rulesBytes = SerializeWithContext(document.Rules,
            RulePackJsonContext.Default.IReadOnlyListRuleDefinition);
        byte[] detectorsBytes = SerializeWithContext(document.Detectors,
            RulePackJsonContext.Default.IReadOnlyListDetectorDefinition);
        byte[] complianceBytes = SerializeWithContext(document.ComplianceRules,
            RulePackJsonContext.Default.IReadOnlyListComplianceRule);
        byte[] entitiesBytes = JsonSerializer.SerializeToUtf8Bytes(
            Array.Empty<RestrictedEntityEntry>());
        byte[] placeholdersBytes = JsonSerializer.SerializeToUtf8Bytes(
            Array.Empty<SecurityPlaceholder>());
        byte[] licensesBytes = JsonSerializer.SerializeToUtf8Bytes(
            Array.Empty<ThirdPartyLicense>());

        string publicKeyBase64 = EcdsaRulePackSigner.GetPublicKeyBase64(privateKey);

        // Start with a placeholder signature and iterate to convergence.
        byte[] sigBytes = Encoding.UTF8.GetBytes(
            """{"algorithm":"","signer_key_id":"","signature_base64":""}""");
        byte[]? prevManifestBytes = null;

        const int maxIterations = 10;
        for (int i = 0; i < maxIterations; i++)
        {
            var fileContents = new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["categories.json"] = categoriesBytes,
                ["assets.json"] = assetsBytes,
                ["rules.json"] = rulesBytes,
                ["detectors.json"] = detectorsBytes,
                ["compliance.json"] = complianceBytes,
                ["dictionaries/entities.json"] = entitiesBytes,
                ["placeholders.json"] = placeholdersBytes,
                ["licenses.json"] = licensesBytes,
                ["signature.json"] = sigBytes,
            };

            var manifest = RulePackWriter.CreateManifest(
                rulePackId, version, minClientVersion, signerKeyId, 1, fileContents);
            byte[] manifestBytes = manifest.ToCanonicalUtf8Bytes();

            // Check for convergence.
            if (prevManifestBytes is not null
                && manifestBytes.AsSpan().SequenceEqual(prevManifestBytes))
            {
                break;
            }

            prevManifestBytes = manifestBytes;

            // Sign the manifest and produce the next iteration's sig.json.
            byte[] signature = EcdsaRulePackSigner.SignManifest(manifestBytes, privateKey);
            string signatureBase64 = Convert.ToBase64String(signature);
            sigBytes = Encoding.UTF8.GetBytes(
                $$"""{"algorithm":"{{EcdsaRulePackSigner.AlgorithmName}}","signer_key_id":"{{EscapeJson(signerKeyId)}}","signature_base64":"{{signatureBase64}}","signer_public_key_base64":"{{publicKeyBase64}}"}""");
        }

        // Build the final ZIP from the converged state.
        var finalFileContents = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["categories.json"] = categoriesBytes,
            ["assets.json"] = assetsBytes,
            ["rules.json"] = rulesBytes,
            ["detectors.json"] = detectorsBytes,
            ["compliance.json"] = complianceBytes,
            ["dictionaries/entities.json"] = entitiesBytes,
            ["placeholders.json"] = placeholdersBytes,
            ["licenses.json"] = licensesBytes,
            ["signature.json"] = sigBytes,
        };

        var finalManifest = RulePackWriter.CreateManifest(
            rulePackId, version, minClientVersion, signerKeyId, 1, finalFileContents);
        byte[] finalManifestBytes = finalManifest.ToCanonicalUtf8Bytes();

        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntry(archive, "manifest.json", finalManifestBytes);

            foreach (var (path, content) in finalFileContents
                .OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                WriteZipEntry(archive, path, content);
            }
        }

        byte[] zipBytes = ms.ToArray();
        string sha256 = Convert.ToHexStringLower(SHA256.HashData(zipBytes));
        return (zipBytes, sha256);
    }

    /// <summary>
    /// Creates a package identical to <paramref name="validZipBytes"/> except
    /// the signature is replaced with one that signs the given bytes instead
    /// of the real manifest, producing an invalid signature.
    /// </summary>
    private static byte[] CreatePackageWithInvalidSignature(
        byte[] validZipBytes, ECDsa wrongKey, string signerKeyId)
    {
        var fileContents = ExtractNonManifestFiles(validZipBytes);

        // Sign with a DIFFERENT key to make the signature invalid.
        byte[] manifestBytes = ExtractEntryBytes(validZipBytes, "manifest.json");
        byte[] badSig = EcdsaRulePackSigner.SignManifest(
            Encoding.UTF8.GetBytes("wrong manifest"), wrongKey);
        string badSigBase64 = Convert.ToBase64String(badSig);
        string publicKeyBase64 = EcdsaRulePackSigner.GetPublicKeyBase64(wrongKey);

        byte[] badSigBytes = Encoding.UTF8.GetBytes(
            $$"""{"algorithm":"{{EcdsaRulePackSigner.AlgorithmName}}","signer_key_id":"{{EscapeJson(signerKeyId)}}","signature_base64":"{{badSigBase64}}","signer_public_key_base64":"{{publicKeyBase64}}"}""");

        fileContents["signature.json"] = badSigBytes;
        return BuildZip(manifestBytes, fileContents);
    }

    /// <summary>
    /// Creates a package where the manifest hash for categories.json does not match
    /// the actual file content. The manifest is kept from the original package;
    /// only the file content is tampered.
    /// </summary>
    private static byte[] CreatePackageWithWrongHash(byte[] validZipBytes)
    {
        var fileContents = ExtractNonManifestFiles(validZipBytes);
        byte[] manifestBytes = ExtractEntryBytes(validZipBytes, "manifest.json");

        // Tamper with categories.json — replace with different content.
        // The manifest still declares the original hash, so the validator will
        // detect a hash mismatch at step 4.
        fileContents["categories.json"] = "{\"categories\":[]}"u8.ToArray();

        return BuildZip(manifestBytes, fileContents);
    }

    /// <summary>
    /// Creates a TrustedSignerStore that trusts the given key pair.
    /// </summary>
    private static TrustedSignerStore CreateTrustedSignerStore(
        string signerKeyId, ECDsa key)
    {
        string publicKeyBase64 = EcdsaRulePackSigner.GetPublicKeyBase64(key);
        string json = $$"""
            {"signers":[{"signer_key_id":"{{signerKeyId}}","public_key_base64":"{{publicKeyBase64}}"}]}
            """;
        return TrustedSignerStore.Load(json);
    }

    /// <summary>
    /// Creates the import service with a temp-directory-backed store.
    /// </summary>
    private static RulePackImportService CreateImportService(
        string basePath, ECDsa testKey, string appVersion)
    {
        var store = new FileRulePackStore(basePath);
        var validator = new RulePackageValidator();
        var policyProvider = new StubPolicyProvider();
        var signerStore = CreateTrustedSignerStore(TestSignerKeyId, testKey);
        return new RulePackImportService(validator, store, policyProvider, signerStore, appVersion);
    }

    // ----------------------------------------------------------------- Tests

    [Fact]
    public async Task Valid_new_package_activates()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var (zipBytes, sha256) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);

            var service = CreateImportService(tempDir, testKey, TestAppVersion);
            var command = new ImportRulePackCommand { ZipBytes = zipBytes };

            ImportResult result = await service.ImportAsync(command, TestContext.Current.CancellationToken);

            Assert.True(result.Success, $"Import should succeed: {result.ErrorCode} — {result.ErrorMessage}");
            Assert.NotNull(result.Active);
            Assert.Equal(TestRulePackId, result.Active!.RulePackId);
            Assert.Equal(TestVersion1, result.Active.Version);
            Assert.Equal(sha256, result.Active.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Invalid_signature_leaves_previous_active()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        using var wrongKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import valid package A.
            var (zipA, sha256A) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult resultA = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipA },
                TestContext.Current.CancellationToken);
            Assert.True(resultA.Success, "Package A import should succeed.");

            // Create package B with an invalid signature (signed with wrong key).
            byte[] zipB = CreatePackageWithInvalidSignature(zipA, wrongKey, TestSignerKeyId);
            ImportResult resultB = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipB, AllowDowngrade = true },
                TestContext.Current.CancellationToken);

            Assert.False(resultB.Success);
            Assert.Equal("SIGNATURE_INVALID", resultB.ErrorCode);

            // Active pointer remains package A.
            var store = new FileRulePackStore(tempDir);
            var active = await store.GetActiveAsync(TestContext.Current.CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(TestVersion1, active!.Version);
            Assert.Equal(sha256A, active.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Invalid_hash_leaves_previous_active()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import valid package A.
            var (zipA, sha256A) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult resultA = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipA },
                TestContext.Current.CancellationToken);
            Assert.True(resultA.Success, "Package A import should succeed.");

            // Create package B with a tampered file (wrong hash).
            byte[] zipB = CreatePackageWithWrongHash(zipA);
            ImportResult resultB = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipB, AllowDowngrade = true },
                TestContext.Current.CancellationToken);

            Assert.False(resultB.Success);

            // Active pointer remains package A.
            var store = new FileRulePackStore(tempDir);
            var active = await store.GetActiveAsync(TestContext.Current.CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(TestVersion1, active!.Version);
            Assert.Equal(sha256A, active.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Incompatible_min_client_version_rejected()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Create a package requiring client 999.0.0 while app is 1.0.0.
            var (zipBytes, _) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "999.0.0", TestSignerKeyId, testKey);

            ImportResult result = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipBytes },
                TestContext.Current.CancellationToken);

            Assert.False(result.Success);
            Assert.Equal("CLIENT_TOO_OLD", result.ErrorCode);
            Assert.NotNull(result.Validation);
            Assert.False(result.Validation!.IsValid);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Newer_version_activates()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import v1.0.0.
            var (zipV1, sha256V1) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r1 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV1 },
                TestContext.Current.CancellationToken);
            Assert.True(r1.Success, "v1.0.0 import should succeed.");

            // Import v2.0.0 (upgrade).
            var (zipV2, sha256V2) = CreateValidPackage(
                document, TestRulePackId, TestVersion2, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r2 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV2 },
                TestContext.Current.CancellationToken);
            Assert.True(r2.Success, "v2.0.0 import should succeed.");

            // Active pointer is v2.0.0.
            var store = new FileRulePackStore(tempDir);
            var active = await store.GetActiveAsync(TestContext.Current.CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(TestVersion2, active!.Version);
            Assert.Equal(sha256V2, active.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Downgrade_without_allow_downgrade_rejected()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import v2.0.0.
            var (zipV2, _) = CreateValidPackage(
                document, TestRulePackId, TestVersion2, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r1 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV2 },
                TestContext.Current.CancellationToken);
            Assert.True(r1.Success, "v2.0.0 import should succeed.");

            // Try import v1.0.0 without AllowDowngrade.
            var (zipV1, _) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r2 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV1, AllowDowngrade = false },
                TestContext.Current.CancellationToken);

            Assert.False(r2.Success);
            Assert.Equal("DOWNGRADE_NOT_ALLOWED", r2.ErrorCode);

            // Active remains v2.0.0.
            var store = new FileRulePackStore(tempDir);
            var active = await store.GetActiveAsync(TestContext.Current.CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(TestVersion2, active!.Version);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Downgrade_with_allow_downgrade_succeeds()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var document = CreateMinimalBaseline();

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import v2.0.0.
            var (zipV2, _) = CreateValidPackage(
                document, TestRulePackId, TestVersion2, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r1 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV2 },
                TestContext.Current.CancellationToken);
            Assert.True(r1.Success, "v2.0.0 import should succeed.");

            // Import v1.0.0 with AllowDowngrade.
            var (zipV1, sha256V1) = CreateValidPackage(
                document, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r2 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipV1, AllowDowngrade = true },
                TestContext.Current.CancellationToken);

            Assert.True(r2.Success, $"Downgrade import should succeed: {r2.ErrorCode}");
            Assert.Equal(TestVersion1, r2.Active!.Version);
            Assert.Equal(sha256V1, r2.Active.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Same_id_version_different_hash_rejected()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "FileRulePackStore requires Windows.");

        using var testKey = EcdsaRulePackSigner.CreateTestKeyPair();
        var documentA = CreateMinimalBaseline();

        // Create a slightly different document (package B).
        var documentB = CreateMinimalBaseline();
        documentB = documentB with
        {
            Categories = documentB.Categories.Select(c => c with { Enabled = false }).ToList(),
        };

        string tempDir = Path.Combine(Path.GetTempPath(), $"srt-import-{Guid.NewGuid():N}");
        try
        {
            var service = CreateImportService(tempDir, testKey, TestAppVersion);

            // Import package A (v1.0.0).
            var (zipA, sha256A) = CreateValidPackage(
                documentA, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);
            ImportResult r1 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipA },
                TestContext.Current.CancellationToken);
            Assert.True(r1.Success, "Package A import should succeed.");

            // Try import package B — same rulePackId, same version, different content (different hash).
            var (zipB, sha256B) = CreateValidPackage(
                documentB, TestRulePackId, TestVersion1, "1.0.0", TestSignerKeyId, testKey);

            // Hashes must differ for this test to be meaningful.
            Assert.NotEqual(sha256A, sha256B);

            ImportResult r2 = await service.ImportAsync(
                new ImportRulePackCommand { ZipBytes = zipB },
                TestContext.Current.CancellationToken);

            Assert.False(r2.Success);
            Assert.Contains("DUPLICATE_VERSION_HASH_MISMATCH", r2.ErrorCode);

            // Active remains package A.
            var store = new FileRulePackStore(tempDir);
            var active = await store.GetActiveAsync(TestContext.Current.CancellationToken);
            Assert.NotNull(active);
            Assert.Equal(sha256A, active!.Sha256);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // ------------------------------------------------------------ Private helpers

    private static byte[] SerializeWithContext<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
    }

    private static void WriteZipEntry(ZipArchive archive, string name, byte[] content)
    {
        string normalized = name.Replace('\\', '/');
        var entry = archive.CreateEntry(normalized, CompressionLevel.Optimal);
        entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

        using var entryStream = entry.Open();
        entryStream.Write(content, 0, content.Length);
    }

    private static byte[] ExtractEntryBytes(byte[] zipBytes, string entryName)
    {
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        var entry = zip.GetEntry(entryName) ?? throw new InvalidOperationException(
            $"Entry '{entryName}' not found in ZIP.");
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Extracts all non-manifest files from a ZIP as a file-name→bytes map.
    /// </summary>
    private static Dictionary<string, byte[]> ExtractNonManifestFiles(byte[] zipBytes)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            string name = entry.FullName.Replace('\\', '/');
            if (name == "manifest.json") continue;

            using var stream = entry.Open();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            result[name] = ms.ToArray();
        }

        return result;
    }

    /// <summary>
    /// Builds a ZIP from a manifest and file contents map.
    /// </summary>
    private static byte[] BuildZip(
        byte[] manifestBytes,
        Dictionary<string, byte[]> fileContents)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntry(archive, "manifest.json", manifestBytes);

            foreach (var (path, content) in fileContents
                .OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                WriteZipEntry(archive, path, content);
            }
        }

        return ms.ToArray();
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

    // --------------------------------------------------------------- Stubs

    private sealed class StubPolicyProvider : IEffectivePolicyProvider
    {
        public Task<EffectivePolicy> BuildAsync(
            ActivePointer active,
            string? localSupplementJson,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new EffectivePolicy());
        }
    }
}
