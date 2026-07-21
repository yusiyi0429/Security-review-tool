using System.Text.Json;
using System.Text.Json.Nodes;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Parsers.Oci;

/// <summary>
/// Parses OCI/Docker JSON artifacts: index.json, manifest.json, and config.
/// Returns strongly-typed representations without mutating the source.
/// </summary>
public static class OciJsonParser
{
    private static readonly JsonDocumentOptions DocOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 32,
    };

    /// <summary>
    /// Parses an OCI index.json or Docker manifest list. Returns the ordered
    /// list of manifest descriptors. Multi-platform indices preserve ordinal.
    /// </summary>
    public static OciIndex ParseIndex(ReadOnlySpan<byte> json, string sourcePath)
    {
        using var ms = new MemoryStream(json.ToArray());
        using var doc = JsonDocument.Parse(ms, DocOptions);
        JsonElement root = doc.RootElement;

        int schemaVersion = root.GetProperty("schemaVersion").GetInt32();
        string mediaType = root.GetProperty("mediaType").GetString() ?? "unknown";

        var manifests = new List<OciDescriptor>();
        foreach (JsonElement entry in root.GetProperty("manifests").EnumerateArray())
        {
            manifests.Add(ParseDescriptor(entry));
        }

        var annotations = ParseStringMap(root, "annotations");
        return new OciIndex(schemaVersion, mediaType, manifests, annotations, sourcePath);
    }

    /// <summary>
    /// Parses an OCI/Docker manifest.json. Returns config descriptor and ordered
    /// layer descriptors.
    /// </summary>
    public static OciManifest ParseManifest(ReadOnlySpan<byte> json, string sourcePath)
    {
        using var ms = new MemoryStream(json.ToArray());
        using var doc = JsonDocument.Parse(ms, DocOptions);
        JsonElement root = doc.RootElement;

        int schemaVersion = root.GetProperty("schemaVersion").GetInt32();
        string mediaType = root.GetProperty("mediaType").GetString() ?? "unknown";

        OciDescriptor config = ParseDescriptor(root.GetProperty("config"));

        var layers = new List<OciDescriptor>();
        foreach (JsonElement entry in root.GetProperty("layers").EnumerateArray())
        {
            layers.Add(ParseDescriptor(entry));
        }

        var annotations = ParseStringMap(root, "annotations");
        return new OciManifest(schemaVersion, mediaType, config, layers, annotations, sourcePath);
    }

    /// <summary>
    /// Parses the config blob (image configuration JSON).
    /// </summary>
    public static OciConfig ParseConfig(ReadOnlySpan<byte> json, string sourcePath)
    {
        using var ms = new MemoryStream(json.ToArray());
        using var doc = JsonDocument.Parse(ms, DocOptions);
        JsonElement root = doc.RootElement;

        string architecture = ReadString(root, "architecture") ?? "unknown";
        string os = ReadString(root, "os") ?? "unknown";

        // rootfs.diff_ids
        var diffIds = new List<string>();
        if (root.TryGetProperty("rootfs", out JsonElement rootfs)
            && rootfs.TryGetProperty("diff_ids", out JsonElement diffIdsArray))
        {
            foreach (JsonElement entry in diffIdsArray.EnumerateArray())
            {
                diffIds.Add(entry.GetString()!);
            }
        }

        // config section
        var env = new List<string>();
        var labels = new Dictionary<string, string>();
        string? entrypoint = null;
        string? cmd = null;
        string? workingDir = null;
        string? user = null;
        var exposedPorts = new List<string>();
        var volumes = new List<string>();

        if (root.TryGetProperty("config", out JsonElement configElem))
        {
            if (configElem.TryGetProperty("Env", out JsonElement envArray))
            {
                foreach (JsonElement e in envArray.EnumerateArray())
                    env.Add(e.GetString()!);
            }

            if (configElem.TryGetProperty("Labels", out JsonElement labelsObj))
            {
                foreach (JsonProperty prop in labelsObj.EnumerateObject())
                    labels[prop.Name] = prop.Value.GetString() ?? "";
            }

            if (configElem.TryGetProperty("Entrypoint", out JsonElement epArray))
            {
                var parts = new List<string>();
                foreach (JsonElement e in epArray.EnumerateArray())
                    parts.Add(e.GetString()!);
                entrypoint = string.Join(" ", parts);
            }

            if (configElem.TryGetProperty("Cmd", out JsonElement cmdArray))
            {
                var parts = new List<string>();
                foreach (JsonElement e in cmdArray.EnumerateArray())
                    parts.Add(e.GetString()!);
                cmd = string.Join(" ", parts);
            }

            workingDir = ReadString(configElem, "WorkingDir");
            user = ReadString(configElem, "User");

            if (configElem.TryGetProperty("ExposedPorts", out JsonElement portsObj))
            {
                foreach (JsonProperty prop in portsObj.EnumerateObject())
                    exposedPorts.Add(prop.Name);
            }

            if (configElem.TryGetProperty("Volumes", out JsonElement volumesObj))
            {
                foreach (JsonProperty prop in volumesObj.EnumerateObject())
                    volumes.Add(prop.Name);
            }
        }

        // history
        var history = new List<OciHistoryEntry>();
        if (root.TryGetProperty("history", out JsonElement historyArray))
        {
            foreach (JsonElement entry in historyArray.EnumerateArray())
            {
                string? created = ReadString(entry, "created");
                string? createdBy = ReadString(entry, "created_by");
                string? comment = ReadString(entry, "comment");
                bool emptyLayer = false;
                if (entry.TryGetProperty("empty_layer", out JsonElement emptyEl))
                    emptyLayer = emptyEl.GetBoolean();

                history.Add(new OciHistoryEntry(created, createdBy, comment, emptyLayer));
            }
        }

        return new OciConfig(
            architecture, os, diffIds, env, labels,
            entrypoint, cmd, workingDir, user,
            exposedPorts, volumes, history, sourcePath);
    }

    private static OciDescriptor ParseDescriptor(JsonElement element)
    {
        string mediaType = element.GetProperty("mediaType").GetString()!;
        long size = element.GetProperty("size").GetInt64();
        string digest = element.GetProperty("digest").GetString()!;

        string? url = ReadString(element, "urls") ?? ReadString(element, "url");
        Platform? platform = null;
        if (element.TryGetProperty("platform", out JsonElement platElem))
        {
            platform = new Platform(
                platElem.GetProperty("architecture").GetString()!,
                platElem.GetProperty("os").GetString()!,
                ReadString(platElem, "os.version"),
                ReadString(platElem, "variant"));
        }

        Dictionary<string, string>? annotations = ParseStringMap(element, "annotations");

        return new OciDescriptor(mediaType, size, digest, url, platform, annotations);
    }

    private static Dictionary<string, string>? ParseStringMap(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out JsonElement obj) || obj.ValueKind != JsonValueKind.Object)
            return null;

        var map = new Dictionary<string, string>();
        foreach (JsonProperty prop in obj.EnumerateObject())
            map[prop.Name] = prop.Value.GetString() ?? "";
        return map.Count > 0 ? map : null;
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out JsonElement prop)
            && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();
        return null;
    }
}

// ---- Result types ----

/// <summary>Parsed OCI index.json or Docker manifest list.</summary>
public sealed record OciIndex(
    int SchemaVersion,
    string MediaType,
    IReadOnlyList<OciDescriptor> Manifests,
    IReadOnlyDictionary<string, string>? Annotations,
    string SourcePath);

/// <summary>Parsed OCI/Docker manifest.</summary>
public sealed record OciManifest(
    int SchemaVersion,
    string MediaType,
    OciDescriptor Config,
    IReadOnlyList<OciDescriptor> Layers,
    IReadOnlyDictionary<string, string>? Annotations,
    string SourcePath);

/// <summary>Parsed image configuration.</summary>
public sealed record OciConfig(
    string Architecture,
    string Os,
    IReadOnlyList<string> RootfsDiffIds,
    IReadOnlyList<string> Env,
    IReadOnlyDictionary<string, string> Labels,
    string? Entrypoint,
    string? Cmd,
    string? WorkingDir,
    string? User,
    IReadOnlyList<string> ExposedPorts,
    IReadOnlyList<string> Volumes,
    IReadOnlyList<OciHistoryEntry> History,
    string SourcePath);

/// <summary>A single history entry from the image config.</summary>
public sealed record OciHistoryEntry(
    string? Created,
    string? CreatedBy,
    string? Comment,
    bool EmptyLayer);
