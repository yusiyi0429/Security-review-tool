using SecurityReview.Domain;

namespace SecurityReview.ParserContracts.Parsing;

public enum ContentKind { Text, StructuredData, Metadata, Binary }

public sealed record LocationMapEntry(long SourceStart, long SourceLength, long TextStart, long TextLength);

public sealed record ContentChunk(
    int ProtocolVersion,
    JobId JobId,
    long Sequence,
    string VirtualPath,
    string FormatId,
    ContentKind ContentKind,
    string? Encoding,
    string Text,
    long SourceStart,
    long SourceLength,
    IReadOnlyList<LocationMapEntry> LocationMap,
    bool IsFinal)
{
    public const int MaxLocationMapEntries = 8_192;
    public const int MaxVirtualPathLength = 4_096;

    public IReadOnlyList<string> Validate(long declaredLength)
    {
        var errors = new List<string>();
        if (Sequence < 0) errors.Add("sequence_negative");
        ValidateVirtualPath(VirtualPath, errors);
        if (SourceStart < 0 || SourceLength < 0)
        {
            errors.Add("source_range_invalid");
        }
        else if (SourceStart > declaredLength || SourceLength > declaredLength - SourceStart)
        {
            errors.Add("source_range_exceeds_declared");
        }

        if (LocationMap.Count > MaxLocationMapEntries)
        {
            errors.Add("location_map_too_large");
        }
        else
        {
            ValidateLocationMap(declaredLength, errors);
        }

        return errors;
    }

    private void ValidateLocationMap(long declaredLength, List<string> errors)
    {
        long previousStart = -1;
        long previousEnd = 0;
        foreach (LocationMapEntry entry in LocationMap)
        {
            if (entry.SourceStart < 0 || entry.SourceLength < 0 || entry.TextStart < 0 || entry.TextLength < 0
                || entry.SourceStart > declaredLength || entry.SourceLength > declaredLength - entry.SourceStart
                || entry.TextStart > Text.Length || entry.TextLength > Text.Length - entry.TextStart)
            {
                errors.Add("location_entry_invalid");
                continue;
            }

            if (entry.SourceStart < previousStart)
            {
                errors.Add("location_map_unsorted");
            }
            else if (entry.SourceStart < previousEnd)
            {
                errors.Add("location_map_overlapping");
            }

            previousStart = entry.SourceStart;
            previousEnd = entry.SourceStart + entry.SourceLength;
        }
    }

    private static void ValidateVirtualPath(string path, List<string> errors)
    {
        if (path.Length == 0)
        {
            errors.Add("virtual_path_empty");
            return;
        }

        if (path.Length > MaxVirtualPathLength) errors.Add("virtual_path_too_long");
        if (path.Contains('\0', StringComparison.Ordinal)) errors.Add("virtual_path_nul");
        if (path[0] is '/' or '\\' || (path.Length >= 2 && char.IsAsciiLetter(path[0]) && path[1] == ':'))
        {
            errors.Add("virtual_path_absolute");
        }

        foreach (string segment in path.Split('/', '\\'))
        {
            if (segment == "..")
            {
                errors.Add("virtual_path_parent_reference");
                break;
            }
        }

        if (!IsWellFormedUnicode(path)) errors.Add("virtual_path_malformed_unicode");
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
