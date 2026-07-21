using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Entry-level guard that validates an archive entry name against
/// <see cref="VirtualPath"/>, reserves budget via
/// <see cref="ArchiveBudget"/>, and produces typed
/// <see cref="CoverageGap"/> / <see cref="ParserEvent"/> values
/// on failure.
/// </summary>
public static class ArchiveEntryGuard
{
    /// <summary>
    /// Attempts to parse the entry name and reserve budget.
    /// Returns a success object or a <see cref="GapProduced"/> event.
    /// </summary>
    public static GuardResult Guard(
        string rawEntryName,
        string parentPath,
        int entryIndex,
        long declaredBytes,
        long compressedBytes,
        int depth,
        ArchiveBudget budget,
        ScanId scanId,
        JobId jobId,
        string formatId)
    {
        // --- 1. validate path ---
        string virtualPath;
        try
        {
            virtualPath = VirtualPath.ParseEntry(rawEntryName, parentPath, entryIndex);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            string pathDetail = ex switch
            {
                ArgumentException ae when ae.Message.Contains("NUL") => "entry_name_nul",
                ArgumentException ae when ae.Message.Contains("surrogate") => "entry_name_surrogate",
                ArgumentException ae when ae.Message.Contains("empty path") || ae.Message.Contains("absolute") => "entry_name_absolute",
                ArgumentException ae when ae.Message.Contains("'..'") => "entry_name_parent_ref",
                ArgumentException ae when ae.Message.Contains("'.'") => "entry_name_dot",
                ArgumentException ae when ae.Message.Contains("drive") => "entry_name_drive",
                ArgumentException ae when ae.Message.Contains("percent") => "entry_name_pct_enc",
                FormatException => "entry_name_too_long",
                _ => "entry_name_invalid",
            };

            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null, $"{parentPath}!/entry[{entryIndex}]", formatId,
                "archive_guard", GapReason.ArchiveLimit, pathDetail,
                declaredBytes, compressedBytes, DateTimeOffset.UtcNow);

            return GuardResult.CreateGap(new ParserEvent.GapProduced(gap));
        }

        // --- 2. reserve budget ---
        var reserveResult = budget.TryReserve(1, declaredBytes, compressedBytes, depth);

        if (reserveResult.Succeeded)
            return GuardResult.Success(virtualPath);

        // --- 3. budget failure ---
        var budgetGap = new CoverageGap(
            Guid.NewGuid(), scanId, null, virtualPath, formatId,
            "archive_guard", GapReason.ArchiveLimit, reserveResult.DetailCode ?? "archive_limit",
            declaredBytes, compressedBytes, DateTimeOffset.UtcNow);

        return GuardResult.CreateGap(new ParserEvent.GapProduced(budgetGap));
    }
}

/// <summary>
/// Result of an <see cref="ArchiveEntryGuard.Guard"/> call:
/// either a successful path resolution or a gap event.
/// </summary>
public readonly record struct GuardResult
{
    private GuardResult(bool succeeded, string? virtualPath, ParserEvent? gap)
    {
        Succeeded = succeeded;
        VirtualPath = virtualPath;
        Gap = gap;
    }

    public bool Succeeded { get; }
    public string? VirtualPath { get; }
    public ParserEvent? Gap { get; }

    public static GuardResult Success(string virtualPath) =>
        new(true, virtualPath, null);

    public static GuardResult CreateGap(ParserEvent gap) =>
        new(false, null, gap);
}
