using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.Parsers.Structured;

/// <summary>
/// Parses JSON sources using streaming <see cref="Utf8JsonReader"/> across
/// 128 KiB buffers. Produces structured content chunks with JSON Pointer
/// locations, rejects duplicate object keys, and handles oversized string
/// tokens via <see cref="OversizeJsonTokenSkipper"/>.
/// </summary>
public sealed class JsonFormatParser : IFormatParser
{
    private const int BufferSize = 128 * 1024; // 128 KiB
    private const int MaxDepth = 128;

    public string ParserId => "json";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "json";
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

        var chunker = new ContentChunker(context.JobId, context.VirtualPath, "json",
            ContentKind.StructuredData, "utf-8", input.DeclaredLength);

        var locationMap = new List<LocationMapEntry>();
        var textOutput = new StringBuilder();
        bool hasContent = false;

        var pathTracker = new JsonPathTracker();
        var duplicateKeyDetector = new DuplicateKeyDetector();

        byte[] rented = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long bytesRead = 0;
            long textCharOffset = 0;
            var state = new JsonReaderState(new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = MaxDepth,
            });

            long sourceLength = input.DeclaredLength;
            bool isFinalBlock = false;

            while (!isFinalBlock)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int read = await stream.ReadAsync(rented.AsMemory(0, BufferSize), cancellationToken)
                    .ConfigureAwait(false);
                isFinalBlock = read < BufferSize || bytesRead + read >= sourceLength;

                var reader = new Utf8JsonReader(
                    rented.AsSpan(0, read), isFinalBlock, state);

                long baseOffset = bytesRead;
                bytesRead += read;

                bool firstRead = true;
                while (firstRead || reader.TokenType != JsonTokenType.None)
                {
                    try
                    {
                        if (!reader.Read())
                        {
                            if (isFinalBlock) break;
                            else break; // need more data
                        }
                        firstRead = false;
                    }
                    catch (JsonException ex)
                    {
                        // Produce gap for corrupt JSON
                        events.Add(new ParserEvent.GapProduced(new CoverageGap(
                            Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                            "json_parse", GapReason.Corrupt,
                            $"json_parse_error: {ex.Message}",
                            sourceLength, bytesRead, DateTimeOffset.UtcNow)));

                        // Emit any content collected before the error
                        if (hasContent)
                        {
                            var remainingChunk = chunker.NextChunk(
                                textOutput.ToString(),
                                0, bytesRead,
                                locationMap, true);
                            events.Add(new ParserEvent.ChunkProduced(remainingChunk));
                        }

                        events.Add(new ParserEvent.ParseCompleted());
                        return events;
                    }

                    long tokenStart = reader.TokenStartIndex;
                    long absoluteStart = baseOffset + tokenStart;

                    switch (reader.TokenType)
                    {
                        case JsonTokenType.StartObject:
                            pathTracker.PushProperty(string.Empty);
                            duplicateKeyDetector.PushObject();
                            EmitToken(textOutput, "{", absoluteStart, 1,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;

                        case JsonTokenType.EndObject:
                            duplicateKeyDetector.PopObject();
                            pathTracker.Pop();
                            EmitToken(textOutput, "}", absoluteStart, 1,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            break;

                        case JsonTokenType.StartArray:
                            pathTracker.PushIndex(0);
                            EmitToken(textOutput, "[", absoluteStart, 1,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;

                        case JsonTokenType.EndArray:
                            pathTracker.Pop();
                            EmitToken(textOutput, "]", absoluteStart, 1,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            break;

                        case JsonTokenType.PropertyName:
                            {
                                string propName = reader.GetString()!;
                                pathTracker.Pop(); // remove previous property/index
                                pathTracker.PushProperty(propName);

                                if (!duplicateKeyDetector.TryAdd(propName))
                                {
                                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                                        "json_parse", GapReason.Corrupt, "json_duplicate_property",
                                        sourceLength, bytesRead, DateTimeOffset.UtcNow)));
                                }

                                EmitToken(textOutput, $"\"{propName}\":", absoluteStart,
                                    (int)reader.ValueSpan.Length + 2,
                                    pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                                break;
                            }

                        case JsonTokenType.String:
                            {
                                string? val = null;
                                try
                                {
                                    val = reader.GetString();
                                }
                                catch (InvalidOperationException)
                                {
                                    // Oversized string token
                                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                                        "json_parse", GapReason.UnsupportedRegion, "json_string_over_limit",
                                        sourceLength, bytesRead, DateTimeOffset.UtcNow)));
                                }

                                if (val != null)
                                {
                                    EmitToken(textOutput, $"\"{val}\"", absoluteStart,
                                        (int)reader.ValueSpan.Length + 2,
                                        pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                                    hasContent = true;
                                }

                                break;
                            }

                        case JsonTokenType.Number:
                            {
                                string numText = Encoding.UTF8.GetString(reader.ValueSpan);
                                EmitToken(textOutput, numText, absoluteStart,
                                    reader.ValueSpan.Length,
                                    pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                                hasContent = true;
                                break;
                            }

                        case JsonTokenType.True:
                            EmitToken(textOutput, "true", absoluteStart, 4,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;

                        case JsonTokenType.False:
                            EmitToken(textOutput, "false", absoluteStart, 5,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;

                        case JsonTokenType.Null:
                            EmitToken(textOutput, "null", absoluteStart, 4,
                                pathTracker.ToJsonPointer(), ref textCharOffset, locationMap);
                            hasContent = true;
                            break;

                        default:
                            break;
                    }
                }

                // Save state for the next buffer
                state = reader.CurrentState;
            }

            // Emit final chunk
            if (textOutput.Length > 0 || !hasContent)
            {
                var finalChunk = chunker.NextChunk(
                    hasContent ? textOutput.ToString() : string.Empty,
                    0, bytesRead, locationMap, true);
                events.Add(new ParserEvent.ChunkProduced(finalChunk));
            }

            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static void EmitToken(StringBuilder sb, string token, long byteStart,
        int byteLength, string jsonPointer, ref long textCharOffset,
        List<LocationMapEntry> locationMap)
    {
        int start = sb.Length;
        if (start > 0) sb.Append(' ');
        sb.Append(token);
        int end = sb.Length;

        locationMap.Add(new LocationMapEntry(
            byteStart, byteLength,
            textCharOffset, end - textCharOffset));
        textCharOffset = end;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
            "json_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    /// <summary>
    /// Tracks property names within the current object to detect duplicates.
    /// </summary>
    private sealed class DuplicateKeyDetector
    {
        private readonly Stack<HashSet<string>> _objects = new();

        public void PushObject()
        {
            _objects.Push(new HashSet<string>(StringComparer.Ordinal));
        }

        public void PopObject()
        {
            if (_objects.Count > 0)
                _objects.Pop();
        }

        /// <summary>Returns false if the key is a duplicate in the current object.</summary>
        public bool TryAdd(string key)
        {
            if (_objects.Count == 0)
                return true;
            return _objects.Peek().Add(key);
        }
    }
}
