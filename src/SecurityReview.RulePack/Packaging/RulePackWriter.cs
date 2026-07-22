using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.RulePack.Packaging;

/// <summary>
/// Writes a rule pack as a deterministic ZIP archive containing exactly 10 files.
/// </summary>
public static class RulePackWriter
{
    private const int FixedZipYear = 1980;
    private const int FixedZipMonth = 1;
    private const int FixedZipDay = 1;

    private static readonly JsonSerializerOptions DtoOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static ReadOnlySpan<byte> SignaturePlaceholderBytes =>
        "{\"algorithm\":\"\",\"signer_key_id\":\"\",\"signature_base64\":\"\"}"u8;

    /// <summary>
    /// Writes a complete rule pack ZIP. Uses a two-pass approach: first writes all
    /// non-manifest files to compute their SHA-256 hashes, populates the manifest,
    /// then writes the final ZIP including the populated manifest.
    /// </summary>
    public static byte[] Write(
        RulePackManifest manifest,
        RulePackDocument document,
        IReadOnlyList<RestrictedEntityEntry> entities,
        IReadOnlyList<SecurityPlaceholder> placeholders,
        IReadOnlyList<ThirdPartyLicense> licenses)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(entities);
        ArgumentNullException.ThrowIfNull(placeholders);
        ArgumentNullException.ThrowIfNull(licenses);

        // Pre-compute all non-manifest entry bytes
        var entries = new Dictionary<string, byte[]>(10, StringComparer.Ordinal)
        {
            ["signature.json"] = SignaturePlaceholderBytes.ToArray(),
            ["categories.json"] = SerializeWithContext(document.Categories,
                RulePackJsonContext.Default.IReadOnlyListCategoryDefinition),
            ["assets.json"] = SerializeWithContext(document.Assets,
                RulePackJsonContext.Default.IReadOnlyListAssetPolicy),
            ["rules.json"] = SerializeWithContext(document.Rules,
                RulePackJsonContext.Default.IReadOnlyListRuleDefinition),
            ["detectors.json"] = SerializeWithContext(document.Detectors,
                RulePackJsonContext.Default.IReadOnlyListDetectorDefinition),
            ["dictionaries/entities.json"] = JsonSerializer.SerializeToUtf8Bytes(entities, DtoOptions),
            ["placeholders.json"] = JsonSerializer.SerializeToUtf8Bytes(placeholders, DtoOptions),
            ["licenses.json"] = JsonSerializer.SerializeToUtf8Bytes(licenses, DtoOptions),
            ["compliance.json"] = SerializeWithContext(document.ComplianceRules,
                RulePackJsonContext.Default.IReadOnlyListComplianceRule),
        };

        // Compute file entries and populate manifest
        var fileEntries = new List<RulePackManifest.FileEntry>(entries.Count);
        foreach (var (path, content) in entries
                     .Where(kv => kv.Key != "signature.json")
                     .OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            string sha256 = Convert.ToHexStringLower(SHA256.HashData(content));
            fileEntries.Add(RulePackManifest.FileEntry.Create(path, sha256, content.Length));
        }

        // Update manifest with computed files
        manifest = manifest with { Files = fileEntries };

        // Now write the full ZIP
        using var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            // manifest.json first (canonical)
            WriteZipEntry(archive, "manifest.json", manifest.ToCanonicalUtf8Bytes());

            // Remaining 8 entries in sorted order for determinism
            foreach (var (path, content) in entries.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                WriteZipEntry(archive, path, content);
            }
        }

        return memoryStream.ToArray();
    }

    /// <summary>
    /// Creates a manifest by computing SHA-256 hashes for each named file's content bytes.
    /// Files are sorted by path.
    /// </summary>
    public static RulePackManifest CreateManifest(
        string rulePackId,
        string version,
        string minClientVersion,
        string signerKeyId,
        int schemaVersion,
        IReadOnlyDictionary<string, byte[]> fileContents)
    {
        ArgumentNullException.ThrowIfNull(rulePackId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentNullException.ThrowIfNull(minClientVersion);
        ArgumentNullException.ThrowIfNull(signerKeyId);
        ArgumentNullException.ThrowIfNull(fileContents);

        var files = new List<RulePackManifest.FileEntry>(fileContents.Count);
        foreach (var (path, content) in fileContents)
        {
            string sha256 = Convert.ToHexStringLower(SHA256.HashData(content));
            files.Add(RulePackManifest.FileEntry.Create(path, sha256, content.Length));
        }

        return RulePackManifest.Create(rulePackId, version, minClientVersion, signerKeyId, schemaVersion, files);
    }

    private static byte[] SerializeWithContext<T>(T value, JsonTypeInfo<T> typeInfo)
    {
        return JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
    }

    private static void WriteZipEntry(ZipArchive archive, string name, byte[] content)
    {
        string normalized = name.Replace('\\', '/');
        var entry = archive.CreateEntry(normalized, CompressionLevel.Optimal);
        entry.LastWriteTime = new DateTimeOffset(FixedZipYear, FixedZipMonth, FixedZipDay, 0, 0, 0, TimeSpan.Zero);

        using var entryStream = entry.Open();
        entryStream.Write(content, 0, content.Length);
    }
}
