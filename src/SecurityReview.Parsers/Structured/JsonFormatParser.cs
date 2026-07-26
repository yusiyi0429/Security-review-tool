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
/// bounded, growable buffers. Produces structured content chunks with JSON
/// Pointer locations, rejects duplicate object keys, and falls back to bounded
/// text coverage when a single token exceeds the structured-parser limit.
/// </summary>
public sealed class JsonFormatParser : IFormatParser
{
    private const int BufferSize = 128 * 1024; // 128 KiB
    private const int MaxBufferedTokenBytes = 1_114_112; // 1 MiB token + framing
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

        byte[] buffer = new byte[BufferSize];
        long totalBytesRead = 0;
        long bufferStart = 0;
        int bufferedBytes = 0;
        bool reachedEof = false;
        long textCharOffset = 0;
        var state = new JsonReaderState(new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = MaxDepth,
        });

        long sourceLength = input.DeclaredLength;
        while (!reachedEof || bufferedBytes > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!reachedEof && bufferedBytes < buffer.Length)
            {
                int read = await stream.ReadAsync(
                        buffer.AsMemory(bufferedBytes, buffer.Length - bufferedBytes),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    reachedEof = true;
                }
                else
                {
                    bufferedBytes += read;
                    totalBytesRead += read;
                }
            }

            var reader = new Utf8JsonReader(
                buffer.AsSpan(0, bufferedBytes), reachedEof, state);

            while (true)
            {
                try
                {
                    if (!reader.Read())
                    {
                        break;
                    }
                }
                catch (JsonException ex)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                        "json_parse", GapReason.Corrupt,
                        $"json_parse_error: {ex.Message}",
                        sourceLength, totalBytesRead, DateTimeOffset.UtcNow)));

                    if (hasContent)
                    {
                        var remainingChunk = chunker.NextChunk(
                            textOutput.ToString(),
                            0, totalBytesRead,
                            locationMap, true);
                        events.Add(new ParserEvent.ChunkProduced(remainingChunk));
                    }

                    events.Add(new ParserEvent.ParseCompleted());
                    return events;
                }

                long tokenStart = reader.TokenStartIndex;
                long absoluteStart = bufferStart + tokenStart;

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
                            pathTracker.Pop();
                            pathTracker.PushProperty(propName);

                            if (!duplicateKeyDetector.TryAdd(propName))
                            {
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                                    "json_parse", GapReason.Corrupt, "json_duplicate_property",
                                    sourceLength, totalBytesRead, DateTimeOffset.UtcNow)));
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
                                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                                    "json_parse", GapReason.UnsupportedRegion,
                                    "json_string_over_limit",
                                    sourceLength, totalBytesRead, DateTimeOffset.UtcNow)));
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
                }
            }

            int consumed = checked((int)reader.BytesConsumed);
            state = reader.CurrentState;
            if (consumed > 0)
            {
                int remaining = bufferedBytes - consumed;
                if (remaining > 0)
                {
                    Buffer.BlockCopy(buffer, consumed, buffer, 0, remaining);
                }

                bufferedBytes = remaining;
                bufferStart += consumed;
            }

            if (reachedEof)
            {
                break;
            }

            if (consumed == 0 && bufferedBytes == buffer.Length)
            {
                if (buffer.Length >= MaxBufferedTokenBytes)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "json",
                        "json_parse", GapReason.UnsupportedRegion,
                        "json_string_over_limit",
                        sourceLength, totalBytesRead, DateTimeOffset.UtcNow)));

                    stream.Position = 0;
                    var textParser = new TextFormatParser();
                    await foreach (ParserEvent fallbackEvent in textParser
                        .ParseAsync(input, context, cancellationToken)
                        .ConfigureAwait(false))
                    {
                        events.Add(fallbackEvent);
                    }

                    return events;
                }

                int newSize = Math.Min(buffer.Length * 2, MaxBufferedTokenBytes);
                Array.Resize(ref buffer, newSize);
            }
        }

        if (textOutput.Length > 0 || !hasContent)
        {
            var finalChunk = chunker.NextChunk(
                hasContent ? textOutput.ToString() : string.Empty,
                0, totalBytesRead, locationMap, true);
            events.Add(new ParserEvent.ChunkProduced(finalChunk));
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
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
