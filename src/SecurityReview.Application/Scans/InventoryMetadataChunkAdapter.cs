using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Converts <see cref="InventoryMetadataUnit"/> values into validated in-process
/// <see cref="ContentChunk"/> records with deterministic job/sequence IDs and
/// <see cref="ContentKind.Metadata"/>. These chunks never cross into a worker;
/// they are consumed by the trusted detector sink.
/// </summary>
public static class InventoryMetadataChunkAdapter
{
    /// <summary>
    /// Converts a metadata unit to a validated <see cref="ContentChunk"/>.
    /// Uses a deterministic <see cref="JobId"/> derived from <paramref name="scanId"/>
    /// so all metadata chunks share the same job identity.
    /// </summary>
    public static ContentChunk Convert(
        InventoryMetadataUnit unit,
        ScanId scanId,
        long sequence)
    {
        ArgumentNullException.ThrowIfNull(unit);

        // Deterministic JobId for all metadata chunks within a scan.
        JobId metadataJobId = DeriveMetadataJobId(scanId);

        // Use Kind.ToString() as the format id so the detector can
        // distinguish metadata kinds.
        string formatId = $"metadata_{unit.Kind.ToString().ToLowerInvariant()}";

        string virtualPath = unit.Locator.ToCanonicalDisplay();

        var chunk = new ContentChunk(
            ProtocolVersion: 1,
            JobId: metadataJobId,
            Sequence: sequence,
            VirtualPath: virtualPath,
            FormatId: formatId,
            ContentKind: ContentKind.Metadata,
            Encoding: null,
            Text: unit.Value,
            SourceStart: 0,
            SourceLength: unit.Value.Length,
            LocationMap: Array.Empty<LocationMapEntry>(),
            IsFinal: true);

        return chunk;
    }

    private static JobId DeriveMetadataJobId(ScanId scanId)
    {
        // UUIDv5-like: namespace = scanId GUID, name = "metadata"
        byte[] namespaceBytes = scanId.Value.ToByteArray();
        byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes("metadata");
        byte[] input = new byte[namespaceBytes.Length + nameBytes.Length];
        namespaceBytes.CopyTo(input, 0);
        nameBytes.CopyTo(input, namespaceBytes.Length);
#pragma warning disable CA5350
        byte[] hash = System.Security.Cryptography.SHA1.HashData(input);
#pragma warning restore CA5350
        Span<byte> uuid = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(uuid);
        uuid[7] = (byte)((uuid[7] & 0x0F) | (5 << 4));
        uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80);
        return new JobId(new Guid(uuid));
    }
}
