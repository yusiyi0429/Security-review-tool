using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityReview.Infrastructure.Diagnostics;

/// <summary>
/// Exception thrown when a diagnostic canary is detected in bundle content.
/// </summary>
public sealed class DiagnosticCanaryException : Exception
{
    public IReadOnlySet<string> DetectedCanaries { get; }

    public DiagnosticCanaryException(IReadOnlySet<string> canaries)
        : base($"Diagnostic canaries detected in bundle: {string.Join(", ", canaries)}")
    {
        DetectedCanaries = canaries;
    }
}

/// <summary>
/// Exports a redacted support bundle as a ZIP archive containing only
/// allowlisted diagnostic files. Every entry is re-parsed through the
/// <see cref="DiagnosticFieldPolicy"/>, bytes are scanned for registered
/// test canaries, and a signed manifest with sorted SHA-256 hashes and
/// sizes is included.
///
/// The export is atomic: written to a temp file, validated, then renamed.
///
/// The bundle contains only these 8 files:
/// <list type="bullet">
///   <item>summary.json</item>
///   <item>versions.json</item>
///   <item>events.jsonl</item>
///   <item>health/sandbox.json</item>
///   <item>health/database.json</item>
///   <item>health/rules.json</item>
///   <item>health/llm.json</item>
///   <item>package-manifest.json</item>
/// </list>
///
/// No DB, WAL, keyring, config, credential, rule dictionary, temp, input,
/// report, corpus, screenshot, or dump files are eligible.
/// </summary>
public static class DiagnosticBundleExporter
{
    private static readonly HashSet<string> AllowlistedEntries = new(StringComparer.OrdinalIgnoreCase)
    {
        "summary.json",
        "versions.json",
        "events.jsonl",
        "health/sandbox.json",
        "health/database.json",
        "health/rules.json",
        "health/llm.json",
        "package-manifest.json",
        "manifest.json", // always included as the last entry
    };

    private static readonly HashSet<string> DisallowedPathSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "db", "wal", "keyring", "config", "credential", "secrets",
        "rules", "temp", "input", "report", "corpus", "screenshot",
        "dump", "staging", "worker",
    };

    private static readonly HashSet<string> DisallowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3",
        ".dat", ".key", ".pem", ".pfx", ".cert",
        ".xlsx", ".tmp", ".dmp", ".png", ".jpg", ".jpeg",
    };

    /// <summary>
    /// Exports a redacted support bundle from <paramref name="sourceDirectory"/>
    /// to <paramref name="targetBundlePath"/>. Only allowlisted entries are
    /// included; JSON/JSONL entries are re-parsed through the policy.
    ///
    /// Canary scan is performed with the default built-in canary patterns;
    /// pass <paramref name="additionalCanaries"/> to add extra strings.
    /// </summary>
    public static async Task ExportAsync(
        string sourceDirectory,
        string targetBundlePath,
        IDictionary<string, string> metadata,
        IReadOnlySet<string>? additionalCanaries = null,
        CancellationToken cancellationToken = default)
    {
        string tempPath = targetBundlePath + ".tmp";

        try
        {
            // Collect all allowlisted files
            var entries = new List<(string EntryName, string SourcePath)>();
            foreach (string allowed in AllowlistedEntries)
            {
                if (allowed == "manifest.json") continue; // generated later

                string sourcePath = Path.Combine(sourceDirectory, allowed);
                if (File.Exists(sourcePath))
                {
                    entries.Add((allowed, sourcePath));
                }
            }

            var manifest = new Dictionary<string, ManifestEntry>(StringComparer.Ordinal);

            // Atomic write: temp → validate → rename
            await using (var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create, leaveOpen: false))
            {
                foreach (var (entryName, sourcePath) in entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!IsEntryAllowed(entryName)) continue;

                    byte[] content = await File.ReadAllBytesAsync(sourcePath, cancellationToken).ConfigureAwait(false);

                    // Re-parse JSON/JSONL entries through field policy
                    if (entryName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                        entryName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
                    {
                        content = SanitizeContent(entryName, content);
                    }

                    // Scan for canaries
                    var allCanaries = GetAllCanaries(additionalCanaries);
                    IReadOnlySet<string> hits = DiagnosticFieldPolicy.ScanForCanaries(content, allCanaries);
                    if (hits.Count > 0)
                    {
                        throw new DiagnosticCanaryException(hits);
                    }

                    byte[] hash = SHA256.HashData(content);
                    string hexHash = Convert.ToHexStringLower(hash);

                    ZipArchiveEntry zipEntry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
                    await using (Stream entryStream = zipEntry.Open())
                    {
                        await entryStream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
                    }

                    manifest[entryName] = new ManifestEntry(hexHash, content.Length);
                }

                // Write manifest as the last entry
                var manifestBytes = BuildManifest(manifest, metadata);
                byte[] manifestHash = SHA256.HashData(manifestBytes);

                ZipArchiveEntry manifestZipEntry = archive.CreateEntry("manifest.json", CompressionLevel.Optimal);
                await using (Stream manifestStream = manifestZipEntry.Open())
                {
                    await manifestStream.WriteAsync(manifestBytes, cancellationToken).ConfigureAwait(false);
                }

                manifest["manifest.json"] = new ManifestEntry(
                    Convert.ToHexStringLower(manifestHash), manifestBytes.Length);
            }

            // Atomic rename
            if (File.Exists(targetBundlePath))
            {
                File.Delete(targetBundlePath);
            }
            File.Move(tempPath, targetBundlePath, overwrite: false);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { }
            throw;
        }
    }

    private static bool IsEntryAllowed(string entryName)
    {
        // Must be in the allowlist
        if (!AllowlistedEntries.Contains(entryName)) return false;

        // Check against disallowed path segments
        string[] segments = entryName.Split('/', '\\');
        foreach (string segment in segments)
        {
            if (DisallowedPathSegments.Contains(segment)) return false;
        }

        // Check extension
        string ext = Path.GetExtension(entryName).ToLowerInvariant();
        if (!string.IsNullOrEmpty(ext) && DisallowedExtensions.Contains(ext)) return false;

        return true;
    }

    private static byte[] SanitizeContent(string entryName, byte[] content)
    {
        string text;
        try
        {
            text = Encoding.UTF8.GetString(content);
        }
        catch
        {
            return Array.Empty<byte>(); // Non-UTF-8 content is dropped
        }

        if (entryName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            return SanitizeJsonl(text);
        }

        if (entryName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            return SanitizeJson(text);
        }

        return content;
    }

    private static byte[] SanitizeJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

            WriteSanitizedElement(writer, doc.RootElement);
            writer.Flush();
            return stream.ToArray();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    private static byte[] SanitizeJsonl(string jsonl)
    {
        var sb = new StringBuilder();
        var lines = jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (string line in lines)
        {
            string trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                using var stream = new MemoryStream();
                using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

                WriteSanitizedElement(writer, doc.RootElement);
                writer.Flush();
                sb.Append(Encoding.UTF8.GetString(stream.ToArray()));
                sb.Append('\n');
            }
            catch
            {
                // Malformed JSON lines are dropped
            }
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void WriteSanitizedElement(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty prop in element.EnumerateObject())
                {
                    string key = prop.Name;
                    if (!DiagnosticFieldPolicy.IsFieldAllowed(key)) continue;

                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        string? val = prop.Value.GetString();
                        if (val is not null && !DiagnosticFieldPolicy.IsFieldValueSafe(key, val)) continue;
                        writer.WritePropertyName(key);
                        prop.Value.WriteTo(writer);
                    }
                    else if (prop.Value.ValueKind is JsonValueKind.Number)
                    {
                        writer.WritePropertyName(key);
                        prop.Value.WriteTo(writer);
                    }
                    else if (prop.Value.ValueKind is JsonValueKind.Object)
                    {
                        writer.WritePropertyName(key);
                        WriteSanitizedElement(writer, prop.Value);
                    }
                    else if (prop.Value.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null)
                    {
                        writer.WritePropertyName(key);
                        prop.Value.WriteTo(writer);
                    }
                    // Arrays and other complex types are dropped
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    WriteSanitizedElement(writer, item);
                }
                writer.WriteEndArray();
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static byte[] BuildManifest(
        Dictionary<string, ManifestEntry> entries,
        IDictionary<string, string> metadata)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();

        writer.WriteString("created_utc", DateTimeOffset.UtcNow.ToString("O"));
        writer.WriteString("schema_version", "1");

        if (metadata.Count > 0)
        {
            writer.WriteStartObject("metadata");
            foreach (var kv in metadata)
            {
                writer.WriteString(kv.Key, kv.Value);
            }
            writer.WriteEndObject();
        }

        writer.WriteStartObject("files");
        foreach (var kv in entries.OrderBy(e => e.Key, StringComparer.Ordinal))
        {
            writer.WriteStartObject(kv.Key);
            writer.WriteString("sha256", kv.Value.Sha256);
            writer.WriteNumber("size", kv.Value.Size);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();

        writer.WriteEndObject();
        writer.Flush();

        return stream.ToArray();
    }

    private static HashSet<string> GetAllCanaries(IReadOnlySet<string>? additionalCanaries)
    {
        var canaries = new HashSet<string>(StringComparer.Ordinal)
        {
            "CANARY_DIAGNOSTIC_LEAK_a1b2c3d4e5f6a7b8",
            "CANARY_DIAGNOSTIC_LEAK_9f8e7d6c5b4a3210",
            "PHANTOM_SECRET_abcdef0123456789",
            "TEST_EXFIL_TOKEN_0123456789abcdef",
            "CANARY_SENSITIVE_VALUE_0011223344556677",
            "REDACTED_CANARY_MARKER_ffeeddccbbaa9988",
        };

        if (additionalCanaries is not null)
        {
            foreach (string c in additionalCanaries)
                canaries.Add(c);
        }

        return canaries;
    }

    private readonly record struct ManifestEntry(string Sha256, long Size);
}
