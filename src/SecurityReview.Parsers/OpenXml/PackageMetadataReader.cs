using DocumentFormat.OpenXml.Packaging;
using SecurityReview.Domain;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Reads document properties (core, extended, custom) from an Open XML package.
/// </summary>
public static class PackageMetadataReader
{
    public static List<ParserEvent.ChunkProduced> Read(
        OpenXmlPackage package,
        ScanId scanId,
        JobId jobId,
        string virtualPath)
    {
        ArgumentNullException.ThrowIfNull(package);

        var chunks = new List<ParserEvent.ChunkProduced>();
        long sequence = 0;

        // Core and app properties are accessible via typed accessors
        TryReadPropertiesPart(package, "/docProps/core.xml",
            jobId, virtualPath, ref sequence, chunks);
        TryReadPropertiesPart(package, "/docProps/app.xml",
            jobId, virtualPath, ref sequence, chunks);

        // Custom properties (any /docProps/custom*.xml)
        foreach (var pair in package.Parts)
        {
            string uri = pair.OpenXmlPart.Uri.ToString();
            if (uri.StartsWith("/docProps/custom", StringComparison.OrdinalIgnoreCase))
            {
                TryReadPropertiesPart(package, uri,
                    jobId, virtualPath, ref sequence, chunks);
            }
        }

        return chunks;
    }

    private static void TryReadPropertiesPart(
        OpenXmlPackage package, string partUri,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            var part = package.Parts
                .FirstOrDefault(p => string.Equals(p.OpenXmlPart.Uri.ToString(), partUri, StringComparison.OrdinalIgnoreCase))
                .OpenXmlPart;

            if (part == null) return;

            using var stream = part.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            using var reader = new StreamReader(stream);
            string text = reader.ReadToEnd();
            if (string.IsNullOrWhiteSpace(text)) return;

            var chunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Metadata,
                "utf-8", text,
                0, text.Length, [], false);

            chunks.Add(new ParserEvent.ChunkProduced(chunk));
        }
        catch
        {
            // Non-critical
        }
    }
}
