using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Binary;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Scans vbaProject.bin for printable ASCII and UTF-16LE strings.
/// Never parses VBA semantics, decompiles modules, or invokes a macro engine.
/// </summary>
public static class VbaVisibleStringReader
{
    public sealed record VbaScanResult(
        IReadOnlyList<ParserEvent.ChunkProduced> Chunks,
        ParserEvent.GapProduced CoverageGap);

    public static VbaScanResult Scan(
        byte[] vbaData,
        ScanId scanId,
        JobId jobId,
        string virtualPath,
        long mediaBaseOffset)
    {
        ArgumentNullException.ThrowIfNull(vbaData);

        var chunks = new List<ParserEvent.ChunkProduced>();
        long sequence = 0;

        var extractionResult = PrintableStringExtractor.Extract(vbaData);

        foreach (var ps in extractionResult.Strings)
        {
            if (ps.IsUtf16BE) continue;

            var locationMap = new List<LocationMapEntry>
            {
                new(ps.ByteOffset, ps.ByteLength, 0, ps.Text.Length)
            };

            var chunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Binary,
                ps.Encoding, ps.Text,
                ps.ByteOffset, ps.ByteLength,
                locationMap.AsReadOnly(), false);

            chunks.Add(new ParserEvent.ChunkProduced(chunk));
        }

        var gap = new CoverageGap(
            Guid.NewGuid(), scanId, null,
            virtualPath, "openxml",
            "vba_string_scan", GapReason.UnsupportedRegion,
            "macro_semantics_not_analyzed",
            vbaData.Length, 0, DateTimeOffset.UtcNow);

        return new VbaScanResult(chunks.AsReadOnly(), new ParserEvent.GapProduced(gap));
    }
}
