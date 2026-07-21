using System.Runtime.CompilerServices;
using System.Globalization;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.Parsers.Pdf;

/// <summary>
/// Implements <see cref="IFormatParser"/> for PDF documents using
/// <see cref="PdfPigAdapter"/> for bounded text extraction,
/// <see cref="PdfCoverageClassifier"/> for per-page coverage,
/// and <see cref="PdfAttachmentGuard"/> for safe embedded-file extraction.
/// </summary>
public sealed class PdfFormatParser : IFormatParser
{
    private const string PdfId = "pdf";

    public string ParserId => PdfId;
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "pdf";
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input,
        ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        List<ParserEvent> events;
        try
        {
            events = await CollectEventsAsync(input, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            events =
            [
                new ParserEvent.GapProduced(CorruptGap(context,
                    "pdf_unexpected: " + ex.GetType().Name)),
                new ParserEvent.ParseCompleted()
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input,
        ParseContext context,
        CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream stream = input.Stream;
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(input));

        long declaredLength = input.DeclaredLength;
        var now = DateTimeOffset.UtcNow;

        // ── Extract pages ────────────────────────────────────
        IReadOnlyList<PdfPageResult> pageResults;
        try
        {
            pageResults = PdfPigAdapter.ExtractPages(stream);
        }
        catch (Exception ex)
        {
            events.Add(new ParserEvent.GapProduced(
                CorruptGap(context, "pdf_open_failed: " + ex.GetType().Name)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Handle document-level error (e.g. encrypted)
        if (pageResults.Count == 1 && pageResults[0].PageNumber == -1 && pageResults[0].HasError)
        {
            var errorPage = pageResults[0];
            GapReason reason = errorPage.ErrorCode == PdfAdapterErrorCode.Encrypted
                ? GapReason.Encrypted
                : GapReason.Corrupt;

            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                PdfId, "pdf_parse", reason,
                errorPage.ErrorCode.ToString(),
                declaredLength, 0, now)));

            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // ── Process each page ────────────────────────────────
        var pageRecords = new List<PdfCoverageClassifier.PageCoverageRecord>();
        long sequence = 0;

        foreach (var pageResult in pageResults)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Classify coverage
            var record = PdfCoverageClassifier.Classify(pageResult);
            pageRecords.Add(record);

            // Emit coverage gap if not covered
            var gap = PdfCoverageClassifier.ToGap(record, context.ScanId,
                context.VirtualPath, now);
            if (gap != null)
                events.Add(new ParserEvent.GapProduced(gap));

            // Emit text chunk if there is text
            if (pageResult.Text.Length > 0)
            {
                var chunk = new ContentChunk(
                    ProtocolVersion: 1,
                    JobId: context.JobId,
                    Sequence: sequence++,
                    VirtualPath: context.VirtualPath,
                    FormatId: PdfId,
                    ContentKind: ContentKind.Text,
                    Encoding: "utf-8",
                    Text: pageResult.Text,
                    SourceStart: 0,
                    SourceLength: declaredLength,
                    LocationMap: pageResult.LocationMap,
                    IsFinal: false);

                var validationErrors = chunk.Validate(declaredLength);
                if (validationErrors.Count == 0)
                {
                    events.Add(new ParserEvent.ChunkProduced(chunk));
                }
            }
        }

        // ── Emit metadata chunk ──────────────────────────────
        try
        {
            var docInfo = PdfPigAdapter.ExtractDocumentInfo(stream);
            if (HasMetadata(docInfo))
            {
                var metadataText = BuildMetadataText(docInfo);
                var metadataChunk = new ContentChunk(
                    ProtocolVersion: 1,
                    JobId: context.JobId,
                    Sequence: sequence++,
                    VirtualPath: context.VirtualPath,
                    FormatId: PdfId,
                    ContentKind: ContentKind.Metadata,
                    Encoding: "utf-8",
                    Text: metadataText,
                    SourceStart: 0,
                    SourceLength: declaredLength,
                    LocationMap: [],
                    IsFinal: false);

                var metaErrors = metadataChunk.Validate(declaredLength);
                if (metaErrors.Count == 0)
                    events.Add(new ParserEvent.ChunkProduced(metadataChunk));
            }
        }
        catch
        {
            // Metadata extraction is best-effort
        }

        // ── Extract annotations as structured data ───────────
        try
        {
            var annotations = PdfPigAdapter.ExtractAnnotations(stream);
            if (annotations.Count > 0)
            {
                var sb = new System.Text.StringBuilder();
                foreach (var a in annotations)
                {
                    if (!string.IsNullOrEmpty(a.Contents))
                        sb.AppendLine(CultureInfo.InvariantCulture,
                            $"Annotation[{a.Subtype}]: {a.Contents}");
                }

                if (sb.Length > 0)
                {
                    var annotChunk = new ContentChunk(
                        ProtocolVersion: 1,
                        JobId: context.JobId,
                        Sequence: sequence++,
                        VirtualPath: context.VirtualPath,
                        FormatId: PdfId,
                        ContentKind: ContentKind.StructuredData,
                        Encoding: "utf-8",
                        Text: sb.ToString(),
                        SourceStart: 0,
                        SourceLength: declaredLength,
                        LocationMap: [],
                        IsFinal: false);

                    var annotErrors = annotChunk.Validate(declaredLength);
                    if (annotErrors.Count == 0)
                        events.Add(new ParserEvent.ChunkProduced(annotChunk));
                }
            }
        }
        catch
        {
            // Annotation extraction is best-effort
        }

        // ── Extract form fields ──────────────────────────────
        try
        {
            var formFields = PdfPigAdapter.ExtractFormFields(stream);
            if (formFields.Count > 0)
            {
                var sb = new System.Text.StringBuilder();
                foreach (var f in formFields)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture,
                        $"FormField[{f.FieldType}]({f.Name}): {f.Value}");
                }

                if (sb.Length > 0)
                {
                    var formChunk = new ContentChunk(
                        ProtocolVersion: 1,
                        JobId: context.JobId,
                        Sequence: sequence++,
                        VirtualPath: context.VirtualPath,
                        FormatId: PdfId,
                        ContentKind: ContentKind.StructuredData,
                        Encoding: "utf-8",
                        Text: sb.ToString(),
                        SourceStart: 0,
                        SourceLength: declaredLength,
                        LocationMap: [],
                        IsFinal: false);

                    var formErrors = formChunk.Validate(declaredLength);
                    if (formErrors.Count == 0)
                        events.Add(new ParserEvent.ChunkProduced(formChunk));
                }
            }
        }
        catch
        {
            // Form field extraction is best-effort
        }

        // ── Extract bookmarks ────────────────────────────────
        try
        {
            var bookmarks = PdfPigAdapter.ExtractBookmarks(stream);
            if (bookmarks.Count > 0)
            {
                var sb = new System.Text.StringBuilder();
                foreach (var b in bookmarks)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"Bookmark: {b.Title}");
                }

                if (sb.Length > 0)
                {
                    var bmChunk = new ContentChunk(
                        ProtocolVersion: 1,
                        JobId: context.JobId,
                        Sequence: sequence++,
                        VirtualPath: context.VirtualPath,
                        FormatId: PdfId,
                        ContentKind: ContentKind.StructuredData,
                        Encoding: "utf-8",
                        Text: sb.ToString(),
                        SourceStart: 0,
                        SourceLength: declaredLength,
                        LocationMap: [],
                        IsFinal: false);

                    var bmErrors = bmChunk.Validate(declaredLength);
                    if (bmErrors.Count == 0)
                        events.Add(new ParserEvent.ChunkProduced(bmChunk));
                }
            }
        }
        catch
        {
            // Bookmark extraction is best-effort
        }

        // ── Process attachments ──────────────────────────────
        try
        {
            var attachments = PdfPigAdapter.EnumerateAttachments(stream);
            if (attachments.Count > 0)
            {
                var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);

                foreach (var att in attachments)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var guard = PdfAttachmentGuard.Guard(
                        stream, att, budget, context.ScanId,
                        context.JobId, context.VirtualPath, now);

                    if (guard.Succeeded && guard.Event != null)
                    {
                        events.Add(guard.Event);
                    }
                    else if (!guard.Succeeded && guard.Event != null)
                    {
                        events.Add(guard.Event);
                    }
                    else if (!guard.Succeeded)
                    {
                        events.Add(new ParserEvent.GapProduced(new CoverageGap(
                            Guid.NewGuid(), context.ScanId, null,
                            context.VirtualPath + "!/" + att.Name,
                            PdfId, "pdf_attachment_guard",
                            GapReason.ArchiveLimit,
                            guard.DetailCode ?? "pdf_attachment_not_safely_extractable",
                            null, null, now)));
                    }
                }
            }
        }
        catch
        {
            // Attachment enumeration is best-effort
        }

        // ── Emit coverage summary ────────────────────────────
        var summary = PdfCoverageClassifier.Summarize(
            pageRecords, context.ScanId, context.VirtualPath, now);

        var summaryText = string.Create(CultureInfo.InvariantCulture,
            $"PDF Coverage: {summary.Status}, " +
            $"{summary.CoveredUnits}/{summary.PlannedUnits} pages covered, " +
            $"{summary.Gaps.Count} gaps");

        var finalChunk = new ContentChunk(
            ProtocolVersion: 1,
            JobId: context.JobId,
            Sequence: sequence++,
            VirtualPath: context.VirtualPath,
            FormatId: PdfId,
            ContentKind: ContentKind.Metadata,
            Encoding: "utf-8",
            Text: summaryText,
            SourceStart: 0,
            SourceLength: declaredLength,
            LocationMap: [],
            IsFinal: false);

        var finalErrors = finalChunk.Validate(declaredLength);
        if (finalErrors.Count == 0)
            events.Add(new ParserEvent.ChunkProduced(finalChunk));

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    // ─── helpers ───────────────────────────────────────────────

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "pdf",
            "pdf_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    private static bool HasMetadata(PdfDocumentInfo info)
    {
        return info.Title != null || info.Author != null || info.Subject != null
            || info.Keywords != null || info.Creator != null || info.Producer != null;
    }

    private static string BuildMetadataText(PdfDocumentInfo info)
    {
        var sb = new System.Text.StringBuilder();
        if (info.Title != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Title: {info.Title}");
        if (info.Author != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Author: {info.Author}");
        if (info.Subject != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Subject: {info.Subject}");
        if (info.Keywords != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Keywords: {info.Keywords}");
        if (info.Creator != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Creator: {info.Creator}");
        if (info.Producer != null)
            sb.AppendLine(CultureInfo.InvariantCulture, $"Producer: {info.Producer}");
        return sb.ToString();
    }
}
