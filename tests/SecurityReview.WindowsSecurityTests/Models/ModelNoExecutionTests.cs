using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Models;

namespace SecurityReview.WindowsSecurityTests.Models;

public sealed class ModelNoExecutionTests
{
    private static string ModelCorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(ModelNoExecutionTests).Assembly.Location)!,
        "Corpus", "Models");

    private static ParseContext MakeContext(string virtualPath) =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));

    /// <summary>
    /// Verifies that pickle files are NEVER deserialized — only metadata
    /// classification occurs.
    /// </summary>
    [Fact]
    public async Task pickle_is_never_deserialized()
    {
        // Even when we process a pickle file through the full parser pipeline,
        // it must never execute pickle bytecode.
        string path = Path.Combine(ModelCorpusDir, "pickle_protocol_2.pkl");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);

        // Static classifier — no deserialization
        var classification = DangerousModelFormatClassifier.Classify(data, ".pkl");
        Assert.True(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.PickleProtocol, classification.Class);

        // Full parser — no deserialization, only gap
        var events = await ParseFileAsync(path, "test.pkl");
        Assert.Contains(events, e => e is ParserEvent.GapProduced);
        Assert.DoesNotContain(events, e => e is ParserEvent.ChunkProduced c &&
            c.Chunk.Text.Contains("pickle.load", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Verifies PyTorch archives are never deserialized.
    /// </summary>
    [Fact]
    public async Task pytorch_archive_is_never_deserialized()
    {
        string path = Path.Combine(ModelCorpusDir, "pytorch_archive.pt");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);

        var classification = DangerousModelFormatClassifier.Classify(data, ".pt");
        Assert.True(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.PyTorchArchive, classification.Class);

        var events = await ParseFileAsync(path, "test.pt");
        // Must produce a gap, not a chunk with deserialized content
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode.Contains("dangerous_object_serialization", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that weight tensor bytes are never semantically covered —
    /// model_weight_semantics_uncovered gap is always emitted.
    /// </summary>
    [Fact]
    public async Task safetensors_weights_not_semantically_covered()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_with_canary_weights.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);

        // Even though canary is in data, the metadata should NOT include
        // the actual weight bytes.
        var chunkText = System.Text.Encoding.UTF8.GetString(data);
        Assert.Contains("ENCRYPTED_SECRET_CANARY", chunkText);

        // The parser must emit the gap and NOT extract canary data as content
        var events = await ParseFileAsync(path, "test.safetensors");
        var chunks = events.OfType<ParserEvent.ChunkProduced>().ToList();
        Assert.DoesNotContain(chunks, c =>
            c.Chunk.Text.Contains("ENCRYPTED_SECRET", StringComparison.Ordinal));

        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");
    }

    /// <summary>
    /// Verifies GGUF weight tensors are never semantically covered.
    /// </summary>
    [Fact]
    public async Task gguf_weights_not_semantically_covered()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_v3_minimal.gguf");
        Assert.True(File.Exists(path));

        var events = await ParseFileAsync(path, "test.gguf");
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");
    }

    /// <summary>
    /// Verifies ONNX raw tensor data is never semantically covered.
    /// </summary>
    [Fact]
    public async Task onnx_raw_tensor_data_not_extracted()
    {
        string path = Path.Combine(ModelCorpusDir, "onnx_with_tensor_data.bin");
        Assert.True(File.Exists(path));

        var events = await ParseFileAsync(path, "test.onnx");
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");

        var chunks = events.OfType<ParserEvent.ChunkProduced>().ToList();
        // The raw_data bytes should not appear in any chunk
        Assert.DoesNotContain(chunks, c =>
            c.Chunk.Text.Contains("SECRET_TENSOR", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that the parsers handle oversized/malicious inputs without
    /// excessive memory allocation or crashes.
    /// </summary>
    [Fact]
    public void all_parsers_handle_malicious_inputs_without_crashes()
    {
        // Test with random binary data — must not throw
        byte[] randomBytes = new byte[4096];
        System.Security.Cryptography.RandomNumberGenerator.Fill(randomBytes);

        // All three parsers should return without throwing
        var st = SafeTensorsHeaderParser.Parse(randomBytes);
        _ = st;

        var gguf = GgufMetadataParser.Parse(randomBytes);
        _ = gguf;

        var onnx = OnnxMetadataWireParser.Parse(randomBytes);
        _ = onnx;

        var cls = DangerousModelFormatClassifier.Classify(randomBytes);
        _ = cls;
    }

    /// <summary>
    /// Verifies that single-byte inputs (truncated) are handled safely.
    /// </summary>
    [Fact]
    public void parsers_handle_single_byte_without_crash()
    {
        byte[] single = [0x80];

        // All must return without throwing
        _ = SafeTensorsHeaderParser.Parse(single);
        _ = GgufMetadataParser.Parse(single);
        _ = OnnxMetadataWireParser.Parse(single);
        _ = DangerousModelFormatClassifier.Classify(single);
    }

    private static async Task<List<ParserEvent>> ParseFileAsync(string filePath, string virtualPath)
    {
        var events = new List<ParserEvent>();
        await using var fs = File.OpenRead(filePath);
        await using var input = new ParserInput(fs, fs.Length);
        var context = MakeContext(virtualPath);
        var parser = new ModelFormatParser();
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }

        return events;
    }
}
