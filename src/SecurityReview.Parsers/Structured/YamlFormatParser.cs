using System.Runtime.CompilerServices;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Parses YAML sources using YamlDotNet's low-level <c>Parser</c> only
/// (never <c>Deserializer</c>, <c>Serializer</c>, type resolver, or tag mapping).
/// Documents ≤ 64 MiB use structured parsing; larger sources fall back to text
/// scanning with <c>yaml_structure_size_limit</c>. Tracks sequence indices,
/// mapping keys, and scalar line/column positions.
/// </summary>
public sealed class YamlFormatParser : IFormatParser
{
    public string ParserId => "yaml";
    public System.Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "yaml";
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

    private async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input, ParseContext context, CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream stream = input.Stream;
        stream.Position = 0;

        long sourceLength = input.DeclaredLength;

        // Size check: > 64 MiB falls back to text scanning
        if (YamlEventGuard.StructureExceedsLimit(sourceLength))
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                "yaml_parse", GapReason.UnsupportedRegion, "yaml_structure_size_limit",
                sourceLength, 0, DateTimeOffset.UtcNow)));

            // Fallback to text content using chunker
            var fallbackChunker = new ContentChunker(context.JobId, context.VirtualPath, ParserId,
                ContentKind.StructuredData, "utf-8", sourceLength);
            var chunk = fallbackChunker.NextChunk("[YAML content exceeds 64 MiB structure limit]",
                0, sourceLength, [], true);
            events.Add(new ParserEvent.ChunkProduced(chunk));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Read entire source for YAML parsing
        int size = (int)sourceLength;
        if (size <= 0) size = 1;
        byte[] buffer = new byte[size];
        int totalRead = await stream.ReadAtLeastAsync(buffer, size, false, cancellationToken)
            .ConfigureAwait(false);

        var textOutput = new StringBuilder();
        var locationMap = new List<LocationMapEntry>();
        long textCharOffset = 0;

        var guard = new YamlEventGuard();

        // Stack for tracking path context (sequence indices, mapping keys)
        var pathStack = new Stack<PathEntry>();

        // Parse YAML events
        using var reader = new StreamReader(new MemoryStream(buffer, 0, totalRead));
        var parser = new YamlDotNet.Core.Parser(reader);

        try
        {
            while (parser.MoveNext())
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!guard.RecordEvent())
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                        "yaml_parse", GapReason.UnsupportedRegion, "yaml_event_limit",
                        sourceLength, 0, DateTimeOffset.UtcNow)));
                    break;
                }

                var evt = parser.Current;

                switch (evt)
                {
                    case StreamStart:
                        EmitEvent(textOutput, "---", ref textCharOffset, locationMap);
                        break;

                    case StreamEnd:
                        EmitEvent(textOutput, "...", ref textCharOffset, locationMap);
                        break;

                    case DocumentStart ds:
                        {
                            if (ds.Tags is { Count: > 0 })
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_custom_tag_unsupported",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                            }

                            EmitEvent(textOutput, "DOCSTART", ref textCharOffset, locationMap);
                            break;
                        }

                    case DocumentEnd:
                        EmitEvent(textOutput, "DOCEND", ref textCharOffset, locationMap);
                        break;

                    case SequenceStart ss:
                        {
                            if (!guard.EnterStructure())
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_depth_limit",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                                break;
                            }

                            if (ss.Tag.IsEmpty == false && ss.Tag.Value != "tag:yaml.org,2002:seq")
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_custom_tag_unsupported",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                            }

                            pathStack.Push(new PathEntry(PathKind.Sequence, 0));
                            if (!ss.Anchor.IsEmpty)
                            {
                                EmitTokenWithLocation(textOutput, $"&{ss.Anchor.Value}",
                                    locationMap, ref textCharOffset,
                                    ss.Start.Line, ss.Start.Column);
                            }
                            EmitEvent(textOutput, "[", ref textCharOffset, locationMap);
                            break;
                        }

                    case SequenceEnd:
                        guard.ExitStructure();
                        if (pathStack.Count > 0) pathStack.Pop();
                        EmitEvent(textOutput, "]", ref textCharOffset, locationMap);
                        break;

                    case MappingStart ms:
                        {
                            if (!guard.EnterStructure())
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_depth_limit",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                                break;
                            }

                            if (ms.Tag.IsEmpty == false && ms.Tag.Value != "tag:yaml.org,2002:map")
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_custom_tag_unsupported",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                            }

                            pathStack.Push(new PathEntry(PathKind.Mapping, 0));
                            if (!ms.Anchor.IsEmpty)
                            {
                                EmitTokenWithLocation(textOutput, $"&{ms.Anchor.Value}",
                                    locationMap, ref textCharOffset,
                                    ms.Start.Line, ms.Start.Column);
                            }
                            EmitEvent(textOutput, "{", ref textCharOffset, locationMap);
                            break;
                        }

                    case MappingEnd:
                        guard.ExitStructure();
                        if (pathStack.Count > 0) pathStack.Pop();
                        EmitEvent(textOutput, "}", ref textCharOffset, locationMap);
                        break;

                    case Scalar scalar:
                        {
                            // Check scalar length
                            if (YamlEventGuard.ScalarExceedsLimit(scalar.Value.Length))
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_scalar_limit",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                                break;
                            }

                            // Check custom tags
                            if (scalar.Tag.IsEmpty == false &&
                                scalar.Tag.Value != "tag:yaml.org,2002:str" &&
                                scalar.Tag.Value != "tag:yaml.org,2002:int" &&
                                scalar.Tag.Value != "tag:yaml.org,2002:float" &&
                                scalar.Tag.Value != "tag:yaml.org,2002:bool" &&
                                scalar.Tag.Value != "tag:yaml.org,2002:null")
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_custom_tag_unsupported",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                            }

                            string pathKey = scalar.IsKey ? "key" : "val";
                            if (pathStack.Count > 0)
                            {
                                var top = pathStack.Pop();
                                if (top.Kind == PathKind.Sequence)
                                {
                                    pathKey = $"[{top.Index}]";
                                    if (!scalar.IsKey)
                                        pathStack.Push(top with { Index = top.Index + 1 });
                                    else
                                        pathStack.Push(top);
                                }
                                else
                                {
                                    pathStack.Push(top);
                                }
                            }

                            string text = scalar.IsKey
                                ? $"{scalar.Value}:"
                                : scalar.Value;

                            // Emit anchor if present
                            if (!scalar.Anchor.IsEmpty)
                            {
                                EmitTokenWithLocation(textOutput, $"&{scalar.Anchor.Value}",
                                    locationMap, ref textCharOffset,
                                    scalar.Start.Line, scalar.Start.Column);
                            }

                            EmitTokenWithLocation(textOutput, text, locationMap,
                                ref textCharOffset, scalar.Start.Line, scalar.Start.Column);

                            break;
                        }

                    case AnchorAlias alias:
                        {
                            if (!guard.RecordAlias(alias.Value.Value))
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                                    "yaml_parse", GapReason.UnsupportedRegion, "yaml_alias_cycle",
                                    sourceLength, 0, DateTimeOffset.UtcNow)));
                                break;
                            }

                            EmitTokenWithLocation(textOutput, $"*{alias.Value.Value}",
                                locationMap, ref textCharOffset,
                                alias.Start.Line, alias.Start.Column);

                            guard.CompleteAlias(alias.Value.Value);
                            break;
                        }

                    case Comment comment:
                        {
                            EmitTokenWithLocation(textOutput, $"# {comment.Value}",
                                locationMap, ref textCharOffset,
                                comment.Start.Line, comment.Start.Column);
                            break;
                        }
                }
            }
        }
        catch (YamlException ex)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, ParserId,
                "yaml_parse", GapReason.Corrupt,
                $"yaml_parse_error: {ex.Message}",
                sourceLength, 0, DateTimeOffset.UtcNow)));
        }

        // Emit chunk
        var chunker = new ContentChunker(context.JobId, context.VirtualPath, ParserId,
            ContentKind.StructuredData, "utf-8", totalRead);

        var finalChunk = chunker.NextChunk(textOutput.ToString(), 0, totalRead,
            locationMap, true);
        events.Add(new ParserEvent.ChunkProduced(finalChunk));
        events.Add(new ParserEvent.ParseCompleted());

        return events;
    }

    private static void EmitEvent(StringBuilder sb, string text, ref long textCharOffset,
        List<LocationMapEntry> map)
    {
        if (sb.Length > 0 && sb[^1] != ' ')
            sb.Append(' ');

        sb.Append(text);
        map.Add(new LocationMapEntry(0, text.Length, textCharOffset, text.Length));
        textCharOffset = sb.Length;
    }

    private static void EmitTokenWithLocation(StringBuilder sb, string text,
        List<LocationMapEntry> map, ref long textCharOffset, long line, long column)
    {
        if (sb.Length > 0 && sb[^1] != ' ')
            sb.Append(' ');

        sb.Append(text);
        map.Add(new LocationMapEntry(
            column, // approximate byte offset from column
            text.Length,
            textCharOffset,
            text.Length));
        textCharOffset = sb.Length;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "yaml",
            "yaml_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    private enum PathKind { Sequence, Mapping }

    private readonly record struct PathEntry(PathKind Kind, int Index);
}
