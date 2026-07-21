using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans.Inventory;

public enum InventoryOutcome { Completed, InputScopeExceeded, RootFailed }

public enum AdsCapability { Available, NotAvailableForFileSystem }

public static class InventoryFailureCodes
{
    public const string InputScopeExceeded = "input_scope_exceeded";
    public const string RootUnavailable = "root_unavailable";
}

public sealed record InventoryBoundaryRecord(string RelativePath, string Code)
{
    public const string ReparsePointNotFollowed = "reparse_point_not_followed";
    public const string DuplicateIdentitySkipped = "duplicate_identity_skipped";
    public const string RootEscapeRejected = "root_escape_rejected";
}

public sealed record InventoryResult(
    IReadOnlyList<FileRecord> Files,
    IReadOnlyList<InventoryMetadataUnit> MetadataUnits,
    IReadOnlyList<CoverageGap> Gaps,
    IReadOnlyList<InventoryBoundaryRecord> BoundaryRecords,
    InventoryOutcome Outcome,
    string? FailureCode,
    long ObservedStreamCount,
    long ObservedTotalBytes,
    AdsCapability AdsCapability);

// Deterministic inventory order: root index, ordinal relative path, ordinal
// stream name (default stream first).
public static class InventoryOrdering
{
    public static IOrderedEnumerable<FileRecord> Order(IEnumerable<FileRecord> records) =>
        records.OrderBy(x => x.RootIndex)
            .ThenBy(x => x.RelativePath, StringComparer.Ordinal)
            .ThenBy(x => x.StreamName ?? string.Empty, StringComparer.Ordinal);
}
