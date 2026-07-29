using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;
using SecurityReview.Parsers.Text;

namespace SecurityReview.UnitTests.Parsers;

/// <summary>
/// End-to-end regression for the large CJK jsonl crash: chunking ->
/// send-time frame splitting -> length-prefixed protocol write/read ->
/// parent-side <see cref="ContentChunk.Validate"/>. No sandbox required;
/// the real <see cref="ContentChunker"/>, <see cref="ContentChunkSplitter"/>,
/// <see cref="LengthPrefixedJsonProtocol"/>, and Validate are chained the
/// same way the worker and parent chain them.
/// </summary>
public sealed class LargeTextFramePipelineTests
{
    // ContentChunker carries 4,096 characters of overlap between consecutive
    // chunks (documented behavior; ContentChunkerTests relies on it too).
    private const int ChunkerOverlapChars = 4_096;

    private static readonly ScanId TestScanId = new(Guid.NewGuid());
    private static readonly JobId TestJobId = new(Guid.NewGuid());

    [Fact]
    public async Task chunked_pipeline_splits_oversize_frames_and_every_frame_writes()
    {
        string text = BuildLargeJsonl();
        long totalSourceLength = Encoding.UTF8.GetByteCount(text);
        IReadOnlyList<ContentChunk> chunks = ChunkAll(text, totalSourceLength);

        // Regression anchor: this content inflates a full 131,072-char chunk
        // past the splitter threshold (CJK -> \\uXXXX, 7 frame bytes/char at
        // the envelope level), so splitting must actually engage.
        Assert.Contains(chunks, c => MeasureFrameBytes(c) > ContentChunkSplitter.MaxChunkFrameBytes);

        var pieces = new List<ContentChunk>();
        foreach (ContentChunk chunk in chunks)
        {
            foreach (ContentChunk piece in SplitOrThrow(chunk))
            {
                int frameBytes = MeasureFrameBytes(piece);
                Assert.True(frameBytes <= ContentChunkSplitter.MaxChunkFrameBytes,
                    $"piece frame is {frameBytes} bytes");
                pieces.Add(piece);
            }
        }

        Assert.True(pieces.Count > chunks.Count);

        // The real write path threw ProtocolException for the original file;
        // every piece must now survive a full write/read round trip.
        IReadOnlyList<ContentChunk> received = await SendAndReceiveAsync(pieces);
        Assert.Equal(pieces.Select(p => p.Text), received.Select(r => r.Text));
    }

    [Fact]
    public void chunked_pipeline_pieces_pass_parent_validation()
    {
        string text = BuildLargeJsonl();
        long totalSourceLength = Encoding.UTF8.GetByteCount(text);
        IReadOnlyList<ContentChunk> chunks = ChunkAll(text, totalSourceLength);

        var pieces = new List<ContentChunk>();
        foreach (ContentChunk chunk in chunks)
        {
            foreach (ContentChunk piece in SplitOrThrow(chunk))
            {
                Assert.Empty(piece.Validate(totalSourceLength));
                pieces.Add(piece);
            }
        }

        // IsFinal is carried only by the very last piece of the final chunk.
        Assert.True(pieces[^1].IsFinal);
        for (int i = 0; i < pieces.Count - 1; i++)
            Assert.False(pieces[i].IsFinal);
    }

    [Fact]
    public void chunked_pipeline_reconstructs_original_text()
    {
        string text = BuildLargeJsonl();
        long totalSourceLength = Encoding.UTF8.GetByteCount(text);
        IReadOnlyList<ContentChunk> chunks = ChunkAll(text, totalSourceLength);

        // Splitting is lossless per chunk.
        foreach (ContentChunk chunk in chunks)
        {
            Assert.Equal(chunk.Text,
                string.Concat(SplitOrThrow(chunk).Select(p => p.Text)));
        }

        // Chunking covers the whole text: consecutive chunks overlap by
        // exactly ChunkerOverlapChars, so trimming that prefix from every
        // non-first chunk must reproduce the original text.
        var reconstructed = new StringBuilder(chunks[0].Text);
        for (int i = 1; i < chunks.Count; i++)
        {
            Assert.True(chunks[i].Text.Length > ChunkerOverlapChars);
            reconstructed.Append(chunks[i].Text.AsSpan(ChunkerOverlapChars));
        }

        Assert.Equal(text, reconstructed.ToString());
    }

    [Fact]
    public async Task single_giant_chunk_like_structured_parser_output_splits_losslessly()
    {
        // A large JSON document shape: JsonFormatParser flattens a whole
        // document into one NextChunk call, producing a single chunk whose
        // serialized frame can exceed MaxFrameBytes (JsonFormatParser.cs:307-313).
        string text = BuildLargeJsonl();
        long totalSourceLength = Encoding.UTF8.GetByteCount(text);
        List<LocationMapEntry> map = BuildUtf8RunMap(text);

        var chunker = new ContentChunker(TestJobId, "assets/big.jsonl", "json",
            ContentKind.StructuredData, "utf-8", totalSourceLength);
        ContentChunk giant = chunker.NextChunk(text, 0, totalSourceLength, map, true);

        // The literal pre-fix crash condition (WriteAsync threw here).
        Assert.True(MeasureFrameBytes(giant) > ProtocolConstants.MaxFrameBytes);

        IReadOnlyList<ContentChunk> pieces = SplitOrThrow(giant);
        Assert.True(pieces.Count > 1);

        IReadOnlyList<ContentChunk> received = await SendAndReceiveAsync(pieces);
        foreach (ContentChunk piece in received)
        {
            Assert.Empty(piece.Validate(totalSourceLength));
        }

        Assert.Equal(text, string.Concat(received.Select(p => p.Text)));
        Assert.True(received[^1].IsFinal);
        for (int i = 0; i < received.Count - 1; i++)
            Assert.False(received[i].IsFinal);
    }

    private static IReadOnlyList<ContentChunk> ChunkAll(string text, long totalSourceLength)
    {
        var chunker = new ContentChunker(TestJobId, "assets/big.jsonl", "text",
            ContentKind.Text, "utf-8", totalSourceLength);
        return chunker.ChunkAll(text, BuildUtf8RunMap(text), totalSourceLength);
    }

    private static IReadOnlyList<ContentChunk> SplitOrThrow(ContentChunk chunk) =>
        ContentChunkSplitter.SplitForFrame(chunk, MeasureFrameBytes)
        ?? throw new InvalidOperationException("Expected the chunk to split.");

    private static async Task<IReadOnlyList<ContentChunk>> SendAndReceiveAsync(
        IReadOnlyList<ContentChunk> pieces)
    {
        using var stream = new MemoryStream();
        foreach (ContentChunk piece in pieces)
        {
            ProtocolEnvelope envelope = ProtocolEnvelope.Create(
                MessageType.ContentChunk, Guid.NewGuid(), Serialize(piece),
                TestScanId, TestJobId);
            await LengthPrefixedJsonProtocol.WriteAsync(stream, envelope,
                CancellationToken.None).ConfigureAwait(false);
        }

        stream.Position = 0;
        var received = new List<ContentChunk>(pieces.Count);
        while (stream.Position < stream.Length)
        {
            ProtocolEnvelope envelope = await LengthPrefixedJsonProtocol
                .ReadAsync(stream, CancellationToken.None).ConfigureAwait(false);
            received.Add(JsonSerializer.Deserialize(envelope.PayloadJson,
                ProtocolJsonContext.Default.ContentChunk)
                ?? throw new InvalidOperationException("Chunk payload round-tripped to null."));
        }

        return received;
    }

    private static string BuildLargeJsonl()
    {
        // ~550K chars (~1.6 MB UTF-8) in three jsonl-shaped lines; the first
        // line is 260K chars (>250 KB), reproducing the reported file shape.
        // Blocks mix escape-dense nested JSON with long CJK runs so the
        // double serialization inflates ~6.6 frame bytes per char.
        string block = BuildDenseBlock();
        var builder = new StringBuilder(560_000);
        int[] lineLengths = [260_000, 200_000, 90_000];
        for (int line = 0; line < lineLengths.Length; line++)
        {
            builder.Append("{\"line\":").Append(line).Append(",\"records\":\"");
            int target = builder.Length + lineLengths[line];
            while (builder.Length < target)
                builder.Append(block);
            builder.Append("\"}\n");
        }

        return builder.ToString();
    }

    private static string BuildDenseBlock()
    {
        var builder = new StringBuilder(180);
        builder.Append("{\\\"secret\\\":\\\"密钥凭证\\\"}");
        while (builder.Length < 170)
            builder.Append("密钥凭证数据备份审计日志记录文件内容机密绝密中文测试");
        return builder.ToString();
    }

    private static List<LocationMapEntry> BuildUtf8RunMap(string text)
    {
        const int runChars = 4_096;
        var map = new List<LocationMapEntry>();
        long bytePosition = 0;
        int charPosition = 0;
        while (charPosition < text.Length)
        {
            int runLength = Math.Min(runChars, text.Length - charPosition);
            if (runLength > 1
                && charPosition + runLength < text.Length
                && char.IsHighSurrogate(text[charPosition + runLength - 1]))
            {
                runLength--;
            }

            long runBytes = Encoding.UTF8.GetByteCount(
                text.AsSpan(charPosition, runLength));
            map.Add(new LocationMapEntry(bytePosition, runBytes, charPosition, runLength));
            bytePosition += runBytes;
            charPosition += runLength;
        }

        return map;
    }

    private static string Serialize(ContentChunk chunk) =>
        JsonSerializer.Serialize(chunk, ProtocolJsonContext.Default.ContentChunk);

    private static int MeasureFrameBytes(ContentChunk chunk)
    {
        // Same double-serialization path as the worker send
        // (WorkerSessionContext.SerializeFrame).
        ProtocolEnvelope envelope = ProtocolEnvelope.Create(
            MessageType.ContentChunk, Guid.NewGuid(), Serialize(chunk),
            TestScanId, TestJobId);
        return JsonSerializer.SerializeToUtf8Bytes(envelope,
            ProtocolJsonContext.Default.ProtocolEnvelope).Length;
    }
}
