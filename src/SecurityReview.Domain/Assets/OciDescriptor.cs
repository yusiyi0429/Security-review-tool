using SecurityReview.Domain.Scans;

namespace SecurityReview.Domain.Assets;

/// <summary>
/// An OCI Distribution Spec descriptor that references a content-addressable
/// blob by digest, size, and media type. Used as the wire-record representation
/// found in index.json and manifest.json — never a runtime fetch target.
/// </summary>
public sealed record OciDescriptor(
    string MediaType,
    long Size,
    string Digest,
    string? Url = null,
    Platform? Platform = null,
    IReadOnlyDictionary<string, string>? Annotations = null)
{
    /// <summary>Well-known media types for OCI/Docker descriptors.</summary>
    public static readonly IReadOnlySet<string> KnownMediaTypes = new HashSet<string>
    {
        // OCI
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        // Docker
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.container.image.v1+json",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.diff.tar",
    };

    /// <summary>
    /// Validates that size matches the actual blob length and that the
    /// digest (when non-null) matches the blob hash. Mismatch produces
    /// a descriptor-scoped gap; the caller should not parse content.
    /// </summary>
    public CoverageGap? ValidateAgainstBlob(string blobPath, long actualSize, string? actualDigest)
    {
        if (Size != actualSize)
        {
            return new CoverageGap(
                Guid.NewGuid(), new ScanId(Guid.Empty), null, blobPath,
                "oci", "descriptor_verify", GapReason.Corrupt,
                $"size_mismatch:declared={Size},actual={actualSize}",
                Size, actualSize, DateTimeOffset.UtcNow);
        }

        if (!string.IsNullOrEmpty(Digest) && actualDigest is not null
            && !string.Equals(Digest, actualDigest, StringComparison.Ordinal))
        {
            return new CoverageGap(
                Guid.NewGuid(), new ScanId(Guid.Empty), null, blobPath,
                "oci", "descriptor_verify", GapReason.Corrupt,
                $"digest_mismatch:declared={Digest},actual={actualDigest}",
                Size, actualSize, DateTimeOffset.UtcNow);
        }

        return null;
    }

    /// <summary>
    /// Returns true when the descriptor carries a recognized OCI/Docker media type.
    /// URLs are metadata-only and never fetched; unsupported types produce
    /// <see cref="GapReason.UnsupportedRegion"/>.
    /// </summary>
    public bool IsKnownMediaType() =>
        KnownMediaTypes.Contains(MediaType);
}

/// <summary>
/// Platform descriptor for multi-platform indices.
/// </summary>
public sealed record Platform(
    string Architecture,
    string Os,
    string? OsVersion = null,
    string? Variant = null);
