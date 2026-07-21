using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Parsers.Pdf;

/// <summary>
/// Guards PDF attachment extraction by inspecting declared stream lengths
/// before materializing bytes. Only extracts when:
/// - Declared length is present, non-negative, and ≤ 64 MiB
/// - The archive budget accepts it
/// If PdfPig cannot provide size before materialization, emits a gap without
/// calling the byte-returning API.
///
/// Safe bytes are wrapped in a bounded stream, sniffed, and emitted as
/// <see cref="ParserEvent.ChildDiscovered"/> with a
/// <c>pdf!/attachment-name</c> virtual path.
/// </summary>
public static class PdfAttachmentGuard
{
    public const long MaxAttachmentBytes = 64 * 1024 * 1024; // 64 MiB

    /// <summary>
    /// Result of an attachment guard check.
    /// </summary>
    public readonly record struct GuardedAttachment
    {
        private GuardedAttachment(bool succeeded, ParserEvent? event_, string? detailCode)
        {
            Succeeded = succeeded;
            Event = event_;
            DetailCode = detailCode;
        }

        public bool Succeeded { get; }
        public ParserEvent? Event { get; }
        public string? DetailCode { get; }

        public static GuardedAttachment Success(ParserEvent childDiscovered) =>
            new(true, childDiscovered, null);

        public static GuardedAttachment Gap(ParserEvent gap, string detailCode) =>
            new(false, gap, detailCode);

        public static GuardedAttachment UnsafeSize(string detailCode) =>
            new(false, null, detailCode);
    }

    /// <summary>
    /// Inspect an attachment's metadata. Extract only when declared length is
    /// present, non-negative, ≤ 64 MiB, and budget accepts it.
    /// </summary>
    public static GuardedAttachment Guard(
        Stream stream,
        PdfAttachmentInfo info,
        ArchiveBudget budget,
        ScanId scanId,
        JobId jobId,
        string parentVirtualPath,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(info);
        ArgumentNullException.ThrowIfNull(budget);

        // If declared length is null, PdfPig cannot determine size before
        // materialization — do not call byte API.
        if (!info.DeclaredLength.HasValue)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null,
                $"{parentVirtualPath}!/{info.Name}",
                "pdf", "pdf_attachment_guard",
                GapReason.ArchiveLimit,
                "pdf_attachment_not_safely_extractable",
                null, null, now);

            return GuardedAttachment.Gap(
                new ParserEvent.GapProduced(gap),
                "pdf_attachment_not_safely_extractable");
        }

        long length = info.DeclaredLength.Value;

        // Reject non-positive length
        if (length <= 0)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null,
                $"{parentVirtualPath}!/{info.Name}",
                "pdf", "pdf_attachment_guard",
                GapReason.ArchiveLimit,
                "pdf_attachment_non_positive",
                length, 0, now);

            return GuardedAttachment.Gap(
                new ParserEvent.GapProduced(gap),
                "pdf_attachment_non_positive");
        }

        // Reject > 64 MiB
        if (length > MaxAttachmentBytes)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null,
                $"{parentVirtualPath}!/{info.Name}",
                "pdf", "pdf_attachment_guard",
                GapReason.ArchiveLimit,
                "pdf_attachment_exceeds_max",
                length, 0, now);

            return GuardedAttachment.Gap(
                new ParserEvent.GapProduced(gap),
                "pdf_attachment_exceeds_max");
        }

        // Check budget: depth = 2 (attachment inside PDF = depth+1 from root)
        int attachmentDepth = 2;
        var reserveResult = budget.TryReserve(1, length, length, attachmentDepth);

        if (!reserveResult.Succeeded)
        {
            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null,
                $"{parentVirtualPath}!/{info.Name}",
                "pdf", "pdf_attachment_guard",
                GapReason.ArchiveLimit,
                reserveResult.DetailCode ?? "archive_budget_exceeded",
                length, length, now);

            return GuardedAttachment.Gap(
                new ParserEvent.GapProduced(gap),
                reserveResult.DetailCode ?? "archive_budget_exceeded");
        }

        // Safe: extract bytes
        byte[] attachmentBytes;
        try
        {
            attachmentBytes = PdfPigAdapter.ExtractAttachmentBytes(stream, info.Name);
        }
        catch (Exception ex)
        {
            // Roll back budget reservation
            budget.Release(length, length);

            var code = MapToAttachmentError(ex);
            var gap = new CoverageGap(
                Guid.NewGuid(), scanId, null,
                $"{parentVirtualPath}!/{info.Name}",
                "pdf", "pdf_attachment_guard",
                GapReason.Corrupt,
                code,
                length, length, now);

            return GuardedAttachment.Gap(
                new ParserEvent.GapProduced(gap), code);
        }

        // Budget reconciliation: release the difference between declared and actual
        if (attachmentBytes.Length < length)
            budget.Release(length - attachmentBytes.Length, length - attachmentBytes.Length);

        // Build virtual path: parentPath + "!/attachment-name"
        string attachmentVirtualPath = $"{parentVirtualPath}!/{info.Name}";

        // Sniff the attachment bytes
        FormatProbe probe;
        try
        {
            using var ms = new MemoryStream(attachmentBytes, writable: false);
            probe = FormatSniffer.ProbeAsync(ms, null, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch
        {
            // Fallback: mark as binary
            probe = new FormatProbe(
                attachmentBytes.AsMemory(0, Math.Min(attachmentBytes.Length, 256)),
                Array.Empty<byte>(), null, attachmentBytes.Length,
                new DetectedFormat("binary", 0.5, ["unknown_attachment"], false));
        }

        byte[] capturedBytes = attachmentBytes;
        Func<CancellationToken, Task<Stream>> streamFactory = _ =>
            Task.FromResult<Stream>(new MemoryStream(capturedBytes, writable: false));

        var childEvent = new ParserEvent.ChildDiscovered(
            attachmentVirtualPath, probe, streamFactory);

        return GuardedAttachment.Success(childEvent);
    }

    private static string MapToAttachmentError(Exception ex)
    {
        string message = ex.Message ?? string.Empty;

        if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
            return "pdf_attachment_not_found";

        if (message.Contains("encrypt", StringComparison.OrdinalIgnoreCase))
            return "pdf_attachment_encrypted";

        if (ex is InvalidOperationException)
            return "pdf_attachment_extraction_failed";

        return "pdf_attachment_unexpected_error";
    }
}
