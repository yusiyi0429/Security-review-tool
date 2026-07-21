using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityReview.RulePack.Packaging;

/// <summary>
/// Manifest describing a rule pack and the integrity of every file inside its ZIP.
/// Serialized as canonical JSON (UTF-8 no BOM, single line, keys sorted, UTC "O" timestamps).
/// </summary>
public sealed record RulePackManifest
{
    public const string ManifestEntryName = "manifest.json";

    public int SchemaVersion { get; init; } = 1;
    public string RulePackId { get; init; } = "";
    public string Version { get; init; } = "";
    public string MinClientVersion { get; init; } = "";
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
    public string SignerKeyId { get; init; } = "";
    public IReadOnlyList<FileEntry> Files { get; init; } = Array.Empty<FileEntry>();

    /// <summary>
    /// Creates a manifest populated with file entries. Files are sorted by path.
    /// </summary>
    public static RulePackManifest Create(
        string rulePackId,
        string version,
        string minClientVersion,
        string signerKeyId,
        int schemaVersion,
        IReadOnlyList<FileEntry> files)
    {
        ArgumentNullException.ThrowIfNull(rulePackId);
        ArgumentNullException.ThrowIfNull(version);
        ArgumentNullException.ThrowIfNull(minClientVersion);
        ArgumentNullException.ThrowIfNull(signerKeyId);
        ArgumentNullException.ThrowIfNull(files);

        var sorted = files
            .OrderBy(f => f.Path, StringComparer.Ordinal)
            .ToArray();

        return new RulePackManifest
        {
            SchemaVersion = schemaVersion,
            RulePackId = rulePackId,
            Version = version,
            MinClientVersion = minClientVersion,
            SignerKeyId = signerKeyId,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            Files = sorted,
        };
    }

    /// <summary>
    /// Serializes the manifest to canonical JSON bytes (UTF-8, no BOM, single line, sorted keys).
    /// </summary>
    public byte[] ToCanonicalUtf8Bytes()
    {
        using var stream = new MemoryStream();
        WriteCanonical(stream);
        return stream.ToArray();
    }

    /// <summary>
    /// Writes the manifest as canonical JSON to <paramref name="stream"/>.
    /// </summary>
    public void WriteCanonical(Stream stream)
    {
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false,
        });

        WriteCanonicalObject(writer);
    }

    private void WriteCanonicalObject(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();

        // Keys sorted alphabetically
        writer.WriteString("created_at_utc", CreatedAtUtc.ToString("O"));

        writer.WriteStartArray("files");
        foreach (var file in Files)
        {
            writer.WriteStartObject();
            writer.WriteString("path", file.Path);
            writer.WriteString("sha256", file.Sha256);
            writer.WriteNumber("size", file.Size);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();

        writer.WriteString("min_client_version", MinClientVersion);
        writer.WriteString("rule_pack_id", RulePackId);
        writer.WriteNumber("schema_version", SchemaVersion);
        writer.WriteString("signer_key_id", SignerKeyId);
        writer.WriteString("version", Version);

        writer.WriteEndObject();
    }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (SchemaVersion <= 0)
            errors.Add("SchemaVersion must be positive.");

        if (string.IsNullOrWhiteSpace(RulePackId))
            errors.Add("RulePackId must not be empty.");

        if (string.IsNullOrWhiteSpace(Version))
            errors.Add("Version must not be empty.");

        if (string.IsNullOrWhiteSpace(MinClientVersion))
            errors.Add("MinClientVersion must not be empty.");

        if (string.IsNullOrWhiteSpace(SignerKeyId))
            errors.Add("SignerKeyId must not be empty.");

        if (Files.Count == 0)
        {
            errors.Add("Files list must not be empty.");
        }
        else
        {
            var paths = new HashSet<string>(StringComparer.Ordinal);
            foreach (var file in Files)
            {
                if (string.IsNullOrWhiteSpace(file.Path))
                {
                    errors.Add("File entry has empty path.");
                }
                else if (!paths.Add(file.Path))
                {
                    errors.Add($"Duplicate file path in manifest: {file.Path}.");
                }

                if (file.Sha256.Length != 64)
                {
                    errors.Add($"SHA-256 for '{file.Path}' must be 64 hex characters; got {file.Sha256.Length}.");
                }

                if (file.Size < 0)
                {
                    errors.Add($"File size for '{file.Path}' must not be negative.");
                }
            }
        }

        return errors;
    }

    /// <summary>
    /// A single file entry inside the rule pack ZIP, referenced by the manifest.
    /// </summary>
    public sealed record FileEntry
    {
        public string Path { get; init; } = "";
        public string Sha256 { get; init; } = "";
        public long Size { get; init; }

        public static FileEntry Create(string path, string sha256Hex, long size) => new()
        {
            Path = path,
            Sha256 = sha256Hex,
            Size = size,
        };
    }
}
