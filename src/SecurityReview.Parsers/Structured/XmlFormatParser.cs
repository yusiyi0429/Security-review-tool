using System.Runtime.CompilerServices;
using System.Text;
using System.Xml;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Parses XML sources using <see cref="XmlReader"/> with DTD processing
/// prohibited, XML resolver disabled, and entity expansion limited to zero.
/// Tracks sibling element indices, attributes, text, comments, and processing
/// instructions. Produces structured content chunks with XPath-like locators.
/// </summary>
public sealed class XmlFormatParser : IFormatParser
{
    public string ParserId => "xml";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "xml";
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input, ParseContext context,
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
                new ParserEvent.GapProduced(CorruptGap(context, $"unexpected: {ex.Message}")),
                new ParserEvent.ParseCompleted(),
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input, ParseContext context, CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream stream = input.Stream;
        stream.Position = 0;

        var settings = new XmlReaderSettings
        {
            Async = true,
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = context.Limits.MaxExpandedBytesRemaining,
            MaxCharactersFromEntities = 0,
            IgnoreComments = false,
            IgnoreProcessingInstructions = false,
            IgnoreWhitespace = false,
        };

        var chunker = new ContentChunker(context.JobId, context.VirtualPath, "xml",
            ContentKind.StructuredData, "utf-8", input.DeclaredLength);

        var locationMap = new List<LocationMapEntry>();
        var textOutput = new StringBuilder();
        long textCharOffset = 0;
        bool hasContent = false;

        // Track element nesting with sibling indices
        var elementStack = new Stack<ElementContext>();

        using var xmlReader = XmlReader.Create(stream, settings);

        try
        {
            while (await xmlReader.ReadAsync().ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();

                switch (xmlReader.NodeType)
                {
                    case XmlNodeType.DocumentType:
                        {
                            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "xml",
                                "xml_parse", GapReason.UnsupportedRegion, "xml_dtd_prohibited",
                                input.DeclaredLength, 0, DateTimeOffset.UtcNow)));
                            break;
                        }

                    case XmlNodeType.XmlDeclaration:
                        {
                            string decl = $"<?xml {xmlReader.Value}?>";
                            EmitToken(textOutput, decl, 0, decl.Length,
                                BuildXPath(elementStack), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;
                        }

                    case XmlNodeType.Element:
                        {
                            if (xmlReader.IsEmptyElement)
                            {
                                // Self-closing tag
                                IncrementSibling(elementStack);
                                string attrs = BuildAttributes(xmlReader);
                                string tag = $"<{xmlReader.Name}{attrs}/>";
                                elementStack.Push(new ElementContext(xmlReader.Name, false));
                                EmitToken(textOutput, tag, 0, tag.Length,
                                    BuildXPath(elementStack), ref textCharOffset, locationMap);
                                elementStack.Pop();
                            }
                            else
                            {
                                IncrementSibling(elementStack);
                                elementStack.Push(new ElementContext(xmlReader.Name, true));
                                string attrs = BuildAttributes(xmlReader);
                                string tag = $"<{xmlReader.Name}{attrs}>";
                                EmitToken(textOutput, tag, 0, tag.Length,
                                    BuildXPath(elementStack), ref textCharOffset, locationMap);
                            }

                            hasContent = true;
                            break;
                        }

                    case XmlNodeType.EndElement:
                        {
                            string tag = $"</{xmlReader.Name}>";
                            EmitToken(textOutput, tag, 0, tag.Length,
                                BuildXPath(elementStack), ref textCharOffset, locationMap);

                            if (elementStack.Count > 0)
                                elementStack.Pop();
                            break;
                        }

                    case XmlNodeType.Text:
                    case XmlNodeType.SignificantWhitespace:
                        {
                            string txt = xmlReader.Value;
                            if (txt.Length > 0)
                            {
                                EmitToken(textOutput, txt, 0, txt.Length,
                                    BuildXPath(elementStack) + "/text()",
                                    ref textCharOffset, locationMap);
                                hasContent = true;
                            }

                            break;
                        }

                    case XmlNodeType.Whitespace:
                        {
                            string ws = xmlReader.Value;
                            EmitToken(textOutput, ws, 0, ws.Length,
                                BuildXPath(elementStack), ref textCharOffset, locationMap);
                            break;
                        }

                    case XmlNodeType.Comment:
                        {
                            string comment = $"<!--{xmlReader.Value}-->";
                            EmitToken(textOutput, comment, 0, comment.Length,
                                BuildXPath(elementStack) + "/comment()",
                                ref textCharOffset, locationMap);
                            hasContent = true;
                            break;
                        }

                    case XmlNodeType.ProcessingInstruction:
                        {
                            string pi = $"<?{xmlReader.Name} {xmlReader.Value}?>";
                            EmitToken(textOutput, pi, 0, pi.Length,
                                BuildXPath(elementStack) + "/pi()",
                                ref textCharOffset, locationMap);
                            hasContent = true;
                            break;
                        }

                    case XmlNodeType.CDATA:
                        {
                            string cdata = $"<![CDATA[{xmlReader.Value}]]>";
                            EmitToken(textOutput, cdata, 0, cdata.Length,
                                BuildXPath(elementStack) + "/text()",
                                ref textCharOffset, locationMap);
                            hasContent = true;
                            break;
                        }
                }
            }
        }
        catch (XmlException ex)
        {
            // Check if the error is DTD-related (DTD prohibited or DTD not supported)
            bool isDtdError = ex.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase);

            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "xml",
                "xml_parse",
                isDtdError ? GapReason.UnsupportedRegion : GapReason.Corrupt,
                isDtdError ? "xml_dtd_prohibited" : $"xml_parse_error: {ex.Message}",
                input.DeclaredLength, 0, DateTimeOffset.UtcNow)));

            if (hasContent)
            {
                var chunk = chunker.NextChunk(textOutput.ToString(), 0,
                    input.DeclaredLength, locationMap, true);
                events.Add(new ParserEvent.ChunkProduced(chunk));
            }

            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Emit final chunk
        if (textOutput.Length > 0 || !hasContent)
        {
            var chunk = chunker.NextChunk(
                hasContent ? textOutput.ToString() : string.Empty,
                0, input.DeclaredLength, locationMap, true);
            events.Add(new ParserEvent.ChunkProduced(chunk));
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static void IncrementSibling(Stack<ElementContext> stack)
    {
        if (stack.Count == 0) return;

        var current = stack.Pop();
        stack.Push(current with { SiblingIndex = current.SiblingIndex + 1 });
    }

    private static string BuildXPath(Stack<ElementContext> stack)
    {
        if (stack.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        foreach (var ctx in stack.Reverse())
        {
            sb.Append('/');
            sb.Append(ctx.Name);
            sb.Append('[');
            sb.Append(ctx.SiblingIndex + 1); // 1-based
            sb.Append(']');
        }

        return sb.ToString();
    }

    private static string BuildAttributes(XmlReader reader)
    {
        if (!reader.HasAttributes)
            return string.Empty;

        var sb = new StringBuilder();
        while (reader.MoveToNextAttribute())
        {
            sb.Append(' ');
            sb.Append(reader.Name);
            sb.Append("=\"");
            sb.Append(reader.Value);
            sb.Append('"');
        }

        reader.MoveToElement();
        return sb.ToString();
    }

    private static void EmitToken(StringBuilder sb, string token, long byteStart,
        int byteLength, string xpath, ref long textCharOffset,
        List<LocationMapEntry> locationMap)
    {
        int start = sb.Length;
        if (start > 0 && sb[sb.Length - 1] != '\n')
            sb.Append(' ');
        sb.Append(token);

        locationMap.Add(new LocationMapEntry(
            byteStart, byteLength,
            textCharOffset, sb.Length - textCharOffset));
        textCharOffset = sb.Length;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "xml",
            "xml_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    private readonly record struct ElementContext(string Name, bool HasChildren)
    {
        public int SiblingIndex { get; init; }
    }
}
