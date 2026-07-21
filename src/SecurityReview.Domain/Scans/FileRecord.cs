using SecurityReview.Domain.Assets;

namespace SecurityReview.Domain.Scans;

public enum InventoryStatus { Complete, MetadataGap }

// One inventoried stream of one file: the default stream (StreamName null) or
// one named alternate data stream. ContentSha256 and FormatId stay null until
// the hashing and detection stages; Coverage starts NotCovered.
public sealed record FileRecord(
    FileId FileId,
    int RootIndex,
    string RelativePath,
    string? EncryptedPathPlaceholder,
    string? StreamName,
    long Length,
    DateTimeOffset LastWriteUtc,
    FileAttributes Attributes,
    FileStreamIdentity Identity,
    IReadOnlyList<AssetTypeId> ComponentAssetTypes,
    InventoryStatus Status,
    string? FormatId,
    string? ContentSha256,
    CoverageStatus Coverage)
{
    public string InventoryKey => string.Create(System.Globalization.CultureInfo.InvariantCulture,
        $"{RootIndex}|{RelativePath}|{StreamName ?? string.Empty}");
}
