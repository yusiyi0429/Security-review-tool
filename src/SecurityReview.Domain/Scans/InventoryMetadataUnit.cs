using SecurityReview.Domain.Findings;

namespace SecurityReview.Domain.Scans;

public enum InventoryMetadataKind { RelativePath, DirectorySegment, FileName, Extension, AdsName }

// Bounded metadata content unit for detection. It is produced for the
// detection rules but is NEVER sent to the parser worker. Values over 4,096
// UTF-16 code units or with malformed Unicode become gaps instead of
// unbounded chunks; hidden/system metadata is never omitted.
public sealed record InventoryMetadataUnit(FileId FileId, InventoryMetadataKind Kind,
    string Value, SourceLocator.PathLocator Locator)
{
    public const int MaxValueUtf16Units = 4_096;

    public static InventoryMetadataUnit? TryCreate(FileId fileId, InventoryMetadataKind kind,
        string value, SourceLocator.PathLocator locator)
    {
        if (value.Length == 0 || value.Length > MaxValueUtf16Units || !IsWellFormedUnicode(value))
        {
            return null;
        }

        return new(fileId, kind, value, locator);
    }

    private static bool IsWellFormedUnicode(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(value[i]))
            {
                return false;
            }
        }

        return true;
    }
}
