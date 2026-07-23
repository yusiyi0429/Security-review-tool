using SecurityReview.Domain;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Application.Scans.Inventory;

public sealed record InventoryRequest(ScanId ScanId, string RootPath,
    IReadOnlyList<AssetComponent> Components, long MaxStreams, long MaxTotalBytes,
    int RootIndex = 0)
{
    public const long DefaultMaxStreams = 100_000;
    public const long DefaultMaxTotalBytes = 10_737_418_240L; // 10 GiB

    public static InventoryRequest Create(ScanId scanId, string rootPath,
        IReadOnlyList<AssetComponent>? components = null, int rootIndex = 0) =>
        new(scanId, rootPath, components ?? [], DefaultMaxStreams, DefaultMaxTotalBytes,
            rootIndex);
}
