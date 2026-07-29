using System.Text;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Text;

namespace SecurityReview.UnitTests.Parsers;

public sealed class ContentChunkerTests
{
    private static readonly JobId TestJobId = new(Guid.NewGuid());

    [Fact]
    public void chunk_all_rebases_location_map_to_chunk_relative_coordinates()
    {
        // 300,000 chars of ASCII (> 131,072 -> multiple chunks). ASCII keeps
        // source byte offset == text char index, so the identity run map lets
        // every rebased entry be resolved back to exact source offsets.
        string text = BuildIndexedAsciiText(300_000);
        List<LocationMapEntry> map = BuildIdentityRunMap(text);

        var chunker = new ContentChunker(TestJobId, "assets/big.log", "text",
            ContentKind.Text, "utf-8", text.Length);
        IReadOnlyList<ContentChunk> chunks = chunker.ChunkAll(text, map, text.Length);

        Assert.True(chunks.Count > 1);
        foreach (ContentChunk chunk in chunks)
        {
            Assert.Empty(chunk.Validate(text.Length));
            foreach (LocationMapEntry entry in chunk.LocationMap)
            {
                Assert.InRange(entry.TextStart, 0, chunk.Text.Length);
                Assert.True(entry.TextLength <= chunk.Text.Length - entry.TextStart,
                    $"entry [{entry.TextStart}+{entry.TextLength}) escapes chunk text of {chunk.Text.Length}");
                if (entry.TextLength > 0)
                {
                    // The rebased entry must still resolve to the same source
                    // character: identity map => source offset == full-text index.
                    Assert.Equal(text[(int)entry.SourceStart], chunk.Text[(int)entry.TextStart]);
                }
            }
        }
    }

    [Fact]
    public void chunk_all_multibyte_text_chunks_validate_and_keep_tail()
    {
        // 300,000 chars (660,000 UTF-8 bytes) force multiple chunks with a
        // non-identity byte/char mapping.
        var builder = new StringBuilder(300_000);
        for (int i = 0; i < 20_000; i++)
            builder.Append("中文密钥测试数据").Append(i.ToString("D6")).Append('；');
        string text = builder.ToString();
        long totalSourceLength = Encoding.UTF8.GetByteCount(text);
        List<LocationMapEntry> map = BuildUtf8RunMap(text);

        var chunker = new ContentChunker(TestJobId, "assets/big.jsonl", "text",
            ContentKind.Text, "utf-8", totalSourceLength);
        IReadOnlyList<ContentChunk> chunks = chunker.ChunkAll(text, map, totalSourceLength);

        Assert.True(chunks.Count > 1);
        foreach (ContentChunk chunk in chunks)
        {
            Assert.Empty(chunk.Validate(totalSourceLength));
            foreach (LocationMapEntry entry in chunk.LocationMap)
            {
                Assert.InRange(entry.TextStart, 0, chunk.Text.Length);
                Assert.True(entry.TextLength <= chunk.Text.Length - entry.TextStart);
            }
        }

        Assert.True(chunks[^1].IsFinal);
        string tailMarker = text[^64..];
        Assert.Contains(chunks, c => c.Text.Contains(tailMarker, StringComparison.Ordinal));
    }

    [Fact]
    public void chunk_all_covers_every_region_of_the_text()
    {
        string text = BuildIndexedAsciiText(300_000);
        List<LocationMapEntry> map = BuildIdentityRunMap(text);

        var chunker = new ContentChunker(TestJobId, "assets/big.log", "text",
            ContentKind.Text, "utf-8", text.Length);
        IReadOnlyList<ContentChunk> chunks = chunker.ChunkAll(text, map, text.Length);

        // Unique indexed blocks make each sampled marker position-sensitive:
        // a dropped region would fail this check even with overlapping chunks.
        foreach (int position in new[] { 0, 50_000, 131_072, 200_000, 262_144, 299_900 })
        {
            string marker = text.Substring(position, 32);
            Assert.Contains(chunks, c => c.Text.Contains(marker, StringComparison.Ordinal));
        }

        Assert.True(chunks[^1].IsFinal);
        for (int i = 0; i < chunks.Count - 1; i++)
            Assert.False(chunks[i].IsFinal);
    }

    [Fact]
    public void next_chunk_emits_large_text_in_full_without_silent_truncation()
    {
        // 1 MiB of escape-dense ASCII. The old estimate-based FitEnvelope
        // shrunk this to fit a 1 MiB envelope and silently dropped the tail;
        // frame safety is now enforced at send time by ContentChunkSplitter.
        string text = new string('"', 1_048_576);
        long sourceLength = text.Length;
        LocationMapEntry[] map = [new LocationMapEntry(0, sourceLength, 0, text.Length)];

        var chunker = new ContentChunker(TestJobId, "assets/huge.log", "text",
            ContentKind.Text, "utf-8", sourceLength);
        ContentChunk chunk = chunker.NextChunk(text, 0, sourceLength, map, true);

        Assert.Equal(text.Length, chunk.Text.Length);
        Assert.Equal(text, chunk.Text);
        Assert.True(chunk.IsFinal);
        Assert.Empty(chunk.Validate(sourceLength));
    }

    private static string BuildIndexedAsciiText(int length)
    {
        // 8-char indexed blocks, truncated to the exact requested length.
        var builder = new StringBuilder(length);
        for (int i = 0; builder.Length < length; i++)
            builder.Append(i.ToString("D8"));
        return builder.ToString(0, length);
    }

    private static List<LocationMapEntry> BuildIdentityRunMap(string text)
    {
        const int runLength = 4_096;
        var map = new List<LocationMapEntry>();
        for (int start = 0; start < text.Length; start += runLength)
        {
            int count = Math.Min(runLength, text.Length - start);
            map.Add(new LocationMapEntry(start, count, start, count));
        }

        return map;
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
                text.Substring(charPosition, runLength));
            map.Add(new LocationMapEntry(bytePosition, runBytes, charPosition, runLength));
            bytePosition += runBytes;
            charPosition += runLength;
        }

        return map;
    }
}
