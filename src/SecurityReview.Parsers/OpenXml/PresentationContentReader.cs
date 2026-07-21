using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SecurityReview.Domain;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Reads text content from PresentationML parts using streamed XmlReader traversal.
/// </summary>
public static class PresentationContentReader
{
    public static List<ParserEvent.ChunkProduced> Read(
        PresentationDocument pres,
        ScanId scanId,
        JobId jobId,
        string virtualPath)
    {
        ArgumentNullException.ThrowIfNull(pres);

        var chunks = new List<ParserEvent.ChunkProduced>();
        long sequence = 0;

        // Slide masters
        if (pres.PresentationPart?.SlideMasterParts != null)
        {
            foreach (var master in pres.PresentationPart.SlideMasterParts)
                ReadPartText(master, jobId, virtualPath, ref sequence, chunks);
        }

        // Each slide + notes
        if (pres.PresentationPart?.SlideParts != null)
        {
            int slideNum = 0;
            foreach (var slide in pres.PresentationPart.SlideParts)
            {
                slideNum++;
                ReadSlideText(slide, slideNum, jobId, virtualPath, ref sequence, chunks);

                if (slide.NotesSlidePart != null)
                    ReadPartText(slide.NotesSlidePart, jobId, virtualPath, ref sequence, chunks);
            }
        }

        // Comments (via Parts enumeration)
        foreach (var pair in pres.Parts)
        {
            string uri = pair.OpenXmlPart.Uri.ToString();
            if (uri.StartsWith("/ppt/comments/", StringComparison.OrdinalIgnoreCase) &&
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

            string text = ExtractDrawingText(stream);
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
        }
    }

    private static void ReadSlideText(
        SlidePart slide, int slideNum,
        JobId jobId, string virtualPath,
        ref long sequence, List<ParserEvent.ChunkProduced> chunks)
    {
        try
        {
            using var stream = slide.GetStream(FileMode.Open, FileAccess.Read);
            if (stream.CanSeek) stream.Position = 0;

            string text = ExtractDrawingText(stream);
            if (!string.IsNullOrWhiteSpace(text))
            {
                var chunk = new ContentChunk(
                    1, jobId, sequence++, virtualPath,
                    "openxml", ContentKind.Text,
                    "utf-8", $"[Slide {slideNum}] {text}",
                    0, 0, [], false);

                chunks.Add(new ParserEvent.ChunkProduced(chunk));
            }
        }
        catch
        {
        }
    }

    private static string ExtractDrawingText(Stream stream)
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

            const string aNs = "http://schemas.openxmlformats.org/drawingml/2006/main";

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.LocalName == "t" && reader.NamespaceURI == aNs)
                {
                    reader.Read();
                    if (reader.NodeType is XmlNodeType.Text or XmlNodeType.Whitespace)
                    {
                        string val = reader.Value;
                        if (!string.IsNullOrEmpty(val))
                            textParts.Add(val);
                    }
                }
            }
        }
        catch (XmlException)
        {
        }

        return string.Join(" ", textParts);
    }
}
