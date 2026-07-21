using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Oci;

namespace SecurityReview.Application.Scans.Oci;

/// <summary>
/// Trusted planner that identifies OCI directory layouts and produces
/// inventory handles for the worker. The planner owns directory traversal;
/// the worker receives only blob handles — never the directory root.
/// </summary>
public sealed class OciLayoutPlanner
{
    /// <summary>
    /// Inspects a directory to determine if it is a valid OCI image layout.
    /// An OCI layout directory must contain both <c>oci-layout</c> and
    /// <c>index.json</c> (or both symlinks/alternate names).
    /// </summary>
    public static bool IsOciLayout(string directoryPath)
    {
        if (string.IsNullOrEmpty(directoryPath) || !Directory.Exists(directoryPath))
        {
            return false;
        }

        return File.Exists(Path.Combine(directoryPath, "oci-layout"))
            && File.Exists(Path.Combine(directoryPath, "index.json"));
    }

    /// <summary>
    /// Reads the <c>oci-layout</c> file and returns its version.
    /// </summary>
    public static string ReadLayoutVersion(string directoryPath)
    {
        string layoutPath = Path.Combine(directoryPath, "oci-layout");
        string json = File.ReadAllText(layoutPath);

        using var doc = System.Text.Json.JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("imageLayoutVersion").GetString() ?? "unknown";
    }

    /// <summary>
    /// Plans all blob handles by parsing <c>index.json</c> and recursively
    /// walking manifests. Returns ordered plan steps the worker must execute.
    /// Each step references a specific blob path (derived from digest), never
    /// the directory root.
    /// </summary>
    public static OciLayoutPlan PlanLayout(string directoryPath, ScanId scanId)
    {
        ArgumentNullException.ThrowIfNull(directoryPath);
        if (!IsOciLayout(directoryPath))
        {
            throw new ArgumentException(
                "Directory is not a valid OCI image layout.", nameof(directoryPath));
        }

        string indexJsonPath = Path.Combine(directoryPath, "index.json");
        byte[] indexJson = File.ReadAllBytes(indexJsonPath);

        OciIndex index = OciJsonParser.ParseIndex(indexJson, indexJsonPath);

        var steps = new List<OciPlanStep>();

        // Step 1: The index itself
        long indexSize = new FileInfo(indexJsonPath).Length;
        steps.Add(new OciPlanStep(
            OciPlanStepKind.ParseIndex,
            indexJsonPath,
            indexSize,
            null,
            index));

        // Step 2: Each manifest
        foreach (var descriptor in index.Manifests)
        {
            // Derive blob path from digest — never use URL
            string? blobPath = DeriveBlobPath(directoryPath, descriptor.Digest);
            if (blobPath == null)
            {
                steps.Add(new OciPlanStep(
                    OciPlanStepKind.Gap,
                    $"digest:{descriptor.Digest}",
                    descriptor.Size,
                    new CoverageGap(
                        Guid.NewGuid(), scanId, null, $"digest:{descriptor.Digest}",
                        "oci", "planner", GapReason.Corrupt,
                        "blob_path_not_derivable", descriptor.Size, 0,
                        DateTimeOffset.UtcNow),
                    null));
                continue;
            }

            if (!descriptor.IsKnownMediaType())
            {
                steps.Add(new OciPlanStep(
                    OciPlanStepKind.Gap,
                    blobPath,
                    descriptor.Size,
                    new CoverageGap(
                        Guid.NewGuid(), scanId, null, blobPath,
                        "oci", "planner", GapReason.UnsupportedRegion,
                        $"unsupported_media_type:{descriptor.MediaType}",
                        descriptor.Size, 0, DateTimeOffset.UtcNow),
                    null));
                continue;
            }

            steps.Add(new OciPlanStep(
                OciPlanStepKind.ParseManifest,
                blobPath,
                descriptor.Size,
                null,
                null,
                descriptor));
        }

        return new OciLayoutPlan(directoryPath, indexJsonPath, index, steps);
    }

    /// <summary>
    /// Plans the next-level blobs for a manifest: config + layers.
    /// The worker calls this after successfully parsing a manifest to get
    /// the next exact blob handles from the trusted broker (this planner).
    /// </summary>
    public static OciLayoutPlan PlanManifestBlobs(
        string directoryPath,
        OciManifest manifest,
        ScanId scanId)
    {
        ArgumentNullException.ThrowIfNull(directoryPath);
        ArgumentNullException.ThrowIfNull(manifest);

        var steps = new List<OciPlanStep>();

        // Config
        string? configPath = DeriveBlobPath(directoryPath, manifest.Config.Digest);
        if (configPath != null)
        {
            steps.Add(new OciPlanStep(
                OciPlanStepKind.ParseConfig,
                configPath,
                manifest.Config.Size,
                null,
                null,
                manifest.Config));
        }
        else
        {
            steps.Add(new OciPlanStep(
                OciPlanStepKind.Gap,
                $"digest:{manifest.Config.Digest}",
                manifest.Config.Size,
                new CoverageGap(
                    Guid.NewGuid(), scanId, null, $"digest:{manifest.Config.Digest}",
                    "oci", "planner", GapReason.Corrupt,
                    "config_blob_path_not_derivable", manifest.Config.Size, 0,
                    DateTimeOffset.UtcNow),
                null));
        }

        // Layers
        for (int i = 0; i < manifest.Layers.Count; i++)
        {
            var layerDescriptor = manifest.Layers[i];
            string? layerPath = DeriveBlobPath(directoryPath, layerDescriptor.Digest);

            if (layerPath != null)
            {
                steps.Add(new OciPlanStep(
                    OciPlanStepKind.ParseLayer,
                    layerPath,
                    layerDescriptor.Size,
                    null,
                    null,
                    layerDescriptor,
                    LayerIndex: i));
            }
            else
            {
                steps.Add(new OciPlanStep(
                    OciPlanStepKind.Gap,
                    $"digest:{layerDescriptor.Digest}",
                    layerDescriptor.Size,
                    new CoverageGap(
                        Guid.NewGuid(), scanId, null, $"digest:{layerDescriptor.Digest}",
                        "oci", "planner", GapReason.Corrupt,
                        "layer_blob_path_not_derivable", layerDescriptor.Size, 0,
                        DateTimeOffset.UtcNow),
                    null,
                    LayerIndex: i));
            }
        }

        return new OciLayoutPlan(directoryPath, manifest.SourcePath, null!, steps);
    }

    /// <summary>
    /// Derives the blob file path from a digest. The path must be exactly
    /// <c>blobs/sha256/&lt;hex&gt;</c> under the layout root. Rejects any
    /// path not derivable from a valid digest.
    /// </summary>
    public static string? DeriveBlobPath(string directoryPath, string digest)
    {
        if (!OciDigest.TryParse(digest, out _, out _))
        {
            return null;
        }

        string hex = digest.Substring("sha256:".Length);
        string blobPath = Path.Combine(directoryPath, "blobs", "sha256", hex);

        // Ensure the resolved path stays under the layout root
        string fullPath = Path.GetFullPath(blobPath);
        string fullRoot = Path.GetFullPath(directoryPath);

        if (!fullPath.StartsWith(fullRoot, StringComparison.Ordinal))
        {
            return null;
        }

        return blobPath;
    }
}

/// <summary>Plan for processing an OCI image layout directory.</summary>
public sealed record OciLayoutPlan(
    string DirectoryPath,
    string IndexPath,
    OciIndex? Index,
    IReadOnlyList<OciPlanStep> Steps);

/// <summary>A single step in the OCI layout processing plan.</summary>
public sealed record OciPlanStep(
    OciPlanStepKind Kind,
    string BlobPath,
    long DeclaredSize,
    CoverageGap? Gap,
    OciIndex? Index = null,
    OciDescriptor? Descriptor = null,
    int? LayerIndex = null);

/// <summary>Kinds of steps in an OCI layout plan.</summary>
public enum OciPlanStepKind
{
    ParseIndex,
    ParseManifest,
    ParseConfig,
    ParseLayer,
    Gap,
}
