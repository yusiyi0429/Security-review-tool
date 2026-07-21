using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SecurityReview.Domain;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Reads text content from WordprocessingML parts using streamed XmlReader traversal.
/// </summary>
public static class WordContentReader
{
    public static List<ParserEvent.ChunkProduced> Read(
        WordprocessingDocument doc,
        ScanId scanId,
        JobId jobId,
        string virtualPath)
    {
        ArgumentNullException.ThrowIfNull(doc);

        var chunks = new List<ParserEvent.ChunkProduced>();
        long sequence = 0;

        // Main document
        if (doc.MainDocumentPart != null)
            ReadPartText(doc.MainDocumentPart, jobId, virtualPath, ref sequence, chunks);

        // Headers
        if (doc.MainDocumentPart?.HeaderParts != null)
        {
            foreach (var header in doc.MainDocumentPart.HeaderParts)
                ReadPartText(header, jobId, virtualPath, ref sequence, chunks);
        }

        // Footers
        if (doc.MainDocumentPart?.FooterParts != null)
        {
            foreach (var footer in doc.MainDocumentPart.FooterParts)
                ReadPartText(footer, jobId, virtualPath, ref sequence, chunks);
        }

        // Comments
        if (doc.MainDocumentPart?.WordprocessingCommentsPart != null)
            ReadPartText(doc.MainDocumentPart.WordprocessingCommentsPart,
                jobId, virtualPath, ref sequence, chunks);

        // Footnotes
        if (doc.MainDocumentPart?.FootnotesPart != null)
            ReadPartText(doc.MainDocumentPart.FootnotesPart,
                jobId, virtualPath, ref sequence, chunks);

        // Endnotes
        if (doc.MainDocumentPart?.EndnotesPart != null)
            ReadPartText(doc.MainDocumentPart.EndnotesPart,
                jobId, virtualPath, ref sequence, chunks);

        // Glossary — also try direct ZIP access if not found via Parts
        // (Glossary is typically accessed through DocumentSettingsPart relationship chain)
        foreach (var pair in doc.Parts)
        {
            string uri = pair.OpenXmlPart.Uri.ToString();
            if (uri.StartsWith("/word/glossary/", StringComparison.OrdinalIgnoreCase))
                ReadPartText(pair.OpenXmlPart, jobId, virtualPath, ref sequence, chunks);
        }

        // Custom XML
        foreach (var pair in doc.Parts)
        {
            string uri = pair.OpenXmlPart.Uri.ToString();
            if (uri.StartsWith("/customXml/", StringComparison.OrdinalIgnoreCase) &&
                uri.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                ReadPartText(pair.OpenXmlPart, jobId, virtualPath, ref sequence, chunks);
        }

        return chunks;
    }

    private static void ReadPartText(
        OpenXmlPart part,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            using var stream = part.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            string text = ExtractWordText(stream);
            if (string.IsNullOrWhiteSpace(text)) return;

            var chunk = new ContentChunk(
                1, jobId, sequence++, virtualPath,
                "openxml", ContentKind.Text,
                "utf-8", text,
                0, text.Length, [], false);

            chunks.Add(new ParserEvent.ChunkProduced(chunk));
        }
        catch
        {
            // Non-fatal
        }
    }

    private static string ExtractWordText(Stream stream)
    {
        var textParts = new List<string>();
        try
        {
            using var reader = XmlReader.Create(stream,
                new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null!,
                    IgnoreWhitespace = true
                });

            const string wNs = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.LocalName == "t" && reader.NamespaceURI == wNs)
                {
                    reader.Read();
                    if (reader.NodeType is XmlNodeType.Text or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace)
                        textParts.Add(reader.Value);
                }
            }
        }
        catch (XmlException)
        {
        }

        return string.Join(" ", textParts);
    }
}
