using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Parsers.Pdf;

/// <summary>
/// Per-page coverage classifier for PDF extraction results.
/// Classifies pages based on text objects, image objects, character count,
/// and parser warnings.
/// 
/// Classification rules:
/// - Text objects + successful text extraction → Covered
/// - Only images, zero text objects → NotCovered (pdf_image_text_requires_ocr)
/// - Both text and images → PartiallyCovered
/// - Parser warning/exception after partial text → PartiallyCovered
/// - Encryption → NotCovered
///
/// The scan summary must not simplify a mixed document to fully covered.
/// </summary>
public static class PdfCoverageClassifier
{
    /// <summary>
    /// Classification result for a single page.
    /// </summary>
    public enum PageCoverage
    {
        /// <summary>Text was successfully extracted from this page.</summary>
        Covered,

        /// <summary>Page has both text and images; some content not fully extractable.</summary>
        PartiallyCovered,

        /// <summary>Page content could not be extracted.</summary>
        NotCovered,
    }

    /// <summary>
    /// Detailed coverage record for a single page.
    /// </summary>
    public sealed record PageCoverageRecord(
        int PageNumber,
        int TextObjects,
        int ImageObjects,
        int CharCount,
        IReadOnlyList<string> Warnings,
        PageCoverage Coverage,
        string DetailCode)
    {
        public string? GapDetail { get; init; }
    }

    /// <summary>
    /// Classify a page result from the adapter.
    /// </summary>
    public static PageCoverageRecord Classify(PdfPageResult page)
    {
        // Check for errors first
        if (page.HasError)
        {
            if (page.ErrorCode == PdfAdapterErrorCode.Encrypted)
            {
                return new PageCoverageRecord(
                    page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                    page.CharCount, page.Warnings,
                    PageCoverage.NotCovered, "encrypted");
            }

            // Other errors → partially covered (may have partial text)
            if (page.Text.Length > 0)
            {
                return new PageCoverageRecord(
                    page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                    page.CharCount, page.Warnings,
                    PageCoverage.PartiallyCovered, "parser_error_with_partial_text");
            }

            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.NotCovered, $"parser_error: {page.ErrorCode}");
        }

        bool hasText = page.TextObjectCount > 0 || page.CharCount > 0;
        bool hasImages = page.ImageObjectCount > 0;
        bool hasWarnings = page.Warnings.Count > 0;

        // Image-only: no text objects and no extracted text
        if (!hasText && hasImages)
        {
            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.NotCovered, "pdf_image_text_requires_ocr");
        }

        // No text and no images → not covered (empty page or unparseable)
        if (!hasText && !hasImages)
        {
            if (page.Text.Length > 0)
            {
                // Text was extracted but no text objects counted → partially covered
                return new PageCoverageRecord(
                    page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                    page.CharCount, page.Warnings,
                    PageCoverage.PartiallyCovered, "text_without_text_objects");
            }

            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.PartiallyCovered, "empty_or_unparseable_page");
        }

        // Both text and images → partially covered
        if (hasText && hasImages)
        {
            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.PartiallyCovered, "mixed_text_images");
        }

        // Text only, no images, no warnings → covered
        if (hasText && !hasImages && !hasWarnings)
        {
            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.Covered, "text_extracted");
        }

        // Text only, but with warnings → partially covered
        if (hasText && !hasImages && hasWarnings)
        {
            return new PageCoverageRecord(
                page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
                page.CharCount, page.Warnings,
                PageCoverage.PartiallyCovered, "text_with_warnings");
        }

        // Default fallback → partially covered
        return new PageCoverageRecord(
            page.PageNumber, page.TextObjectCount, page.ImageObjectCount,
            page.CharCount, page.Warnings,
            PageCoverage.PartiallyCovered, "unknown_coverage_state");
    }

    /// <summary>
    /// Produce a <see cref="CoverageGap"/> from a page classification when not covered.
    /// </summary>
    public static CoverageGap? ToGap(PageCoverageRecord record, ScanId scanId,
        string virtualPath, DateTimeOffset now)
    {
        if (record.Coverage == PageCoverage.Covered)
            return null;

        GapReason reason = record.Coverage switch
        {
            PageCoverage.NotCovered when record.DetailCode == "encrypted" => GapReason.Encrypted,
            PageCoverage.NotCovered => GapReason.UnsupportedRegion,
            PageCoverage.PartiallyCovered => GapReason.UnsupportedRegion,
            _ => GapReason.UnsupportedRegion,
        };

        return new CoverageGap(
            Guid.NewGuid(), scanId, null,
            $"{virtualPath}#page={record.PageNumber}",
            "pdf", "pdf_classifier", reason,
            record.DetailCode,
            null, null, now);
    }

    /// <summary>
    /// Compute a <see cref="CoverageSummary"/> from a list of page records,
    /// ensuring mixed documents are never simplified to fully covered.
    /// </summary>
    public static CoverageSummary Summarize(IReadOnlyList<PageCoverageRecord> pages,
        ScanId scanId, string virtualPath, DateTimeOffset now)
    {
        int plannedUnits = pages.Count;
        if (plannedUnits == 0)
            return CoverageSummary.Create(0, 0, []);

        int coveredUnits = pages.Count(p => p.Coverage == PageCoverage.Covered);
        bool hasMixed = pages.Any(p => p.Coverage == PageCoverage.PartiallyCovered);
        bool hasNotCovered = pages.Any(p => p.Coverage == PageCoverage.NotCovered);

        var gaps = new List<CoverageGap>();
        foreach (var page in pages)
        {
            var gap = ToGap(page, scanId, virtualPath, now);
            if (gap != null)
                gaps.Add(gap);
        }

        // Determine overall status. Mixed must not simplify to fully covered.
        CoverageStatus status;
        if (hasNotCovered && coveredUnits == 0 && !hasMixed)
            status = CoverageStatus.NotCovered;
        else if (hasMixed || hasNotCovered)
            status = CoverageStatus.PartiallyCovered;
        else if (coveredUnits == plannedUnits && gaps.Count == 0)
            status = CoverageStatus.Covered;
        else
            status = CoverageStatus.PartiallyCovered;

        return new CoverageSummary(plannedUnits, coveredUnits, gaps, status);
    }
}
