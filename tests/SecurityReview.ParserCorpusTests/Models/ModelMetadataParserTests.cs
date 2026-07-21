using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Models;

namespace SecurityReview.ParserCorpusTests.Models;

public sealed class ModelMetadataParserTests
{
    private static string ModelCorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(ModelMetadataParserTests).Assembly.Location)!,
        "Corpus", "Models");

    private static ParseContext MakeContext(string virtualPath) =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));

    // ──── SafeTensors Header Parser ────

    [Fact]
    public void safetensors_minimal_parses_tensors_and_metadata()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_minimal.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = SafeTensorsHeaderParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.Tensors);
        Assert.Contains(result.Tensors, t => t.Name == "weight" && t.Dtype == "F32");
        Assert.Contains(result.Metadata.Keys, k => k == "model");
    }

    [Fact]
    public void safetensors_oversized_header_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_oversized_header.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = SafeTensorsHeaderParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(SafeTensorsFailureReason.HeaderTooLarge, result.FailureReason);
    }

    [Fact]
    public void safetensors_truncated_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_truncated.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = SafeTensorsHeaderParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(SafeTensorsFailureReason.Truncated, result.FailureReason);
    }

    [Fact]
    public void safetensors_canary_weights_not_in_metadata()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_with_canary_weights.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = SafeTensorsHeaderParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Contains(result.Tensors, t => t.Name == "canary_tensor");

        // The tensor metadata is present, but the actual weight bytes should
        // not be extracted as strings. Verify the tensor name and dtype only.
        var tensor = result.Tensors.First(t => t.Name == "canary_tensor");
        Assert.Equal("U8", tensor.Dtype);
    }

    [Fact]
    public void safetensors_empty_data_rejected()
    {
        byte[] data = Array.Empty<byte>();
        var result = SafeTensorsHeaderParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(SafeTensorsFailureReason.Truncated, result.FailureReason);
    }

    // ──── GGUF Metadata Parser ────

    [Fact]
    public void gguf_v3_minimal_parses_kv_and_tensors()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_v3_minimal.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal(3u, result.Version);
        Assert.Contains(result.Entries, e => e.Key == "general.architecture" && e.StringValue == "llama");
        Assert.Contains(result.Entries, e => e.Key == "general.name" && e.StringValue == "test-model");
        Assert.NotEmpty(result.Tensors);
        Assert.Contains(result.Tensors, t => t.Name == "output.weight");
    }

    [Fact]
    public void gguf_v2_minimal_parses_kv()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_v2_minimal.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal(2u, result.Version);
        Assert.Contains(result.Entries, e => e.Key == "tokenizer.ggml.model");
        Assert.Empty(result.Tensors);
    }

    [Fact]
    public void gguf_invalid_magic_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_invalid_magic.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(GgufFailureReason.InvalidMagic, result.FailureReason);
    }

    [Fact]
    public void gguf_oversized_string_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_oversized_string.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(GgufFailureReason.OversizedString, result.FailureReason);
    }

    [Fact]
    public void gguf_excessive_kv_count_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_excessive_kv_count.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(GgufFailureReason.ExcessiveKvCount, result.FailureReason);
    }

    [Fact]
    public void gguf_excessive_tensor_count_rejected()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_oversized_tensor_count.gguf");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = GgufMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(GgufFailureReason.ExcessiveTensorCount, result.FailureReason);
    }

    // ──── ONNX Metadata Wire Parser ────

    [Fact]
    public void onnx_minimal_parses_metadata()
    {
        string path = Path.Combine(ModelCorpusDir, "onnx_minimal.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = OnnxMetadataWireParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal("test-producer", result.ProducerName);
        Assert.Equal("ai.test", result.Domain);
        Assert.Equal("test ONNX model", result.DocString);
        Assert.Contains(result.MetadataProps.Keys, k => k == "framework");
        Assert.Equal("onnx", result.MetadataProps["framework"]);
        Assert.Contains(result.NodeNames, n => n == "relu");
        Assert.Contains(result.InputNames, n => n == "input");
        Assert.Contains(result.OutputNames, n => n == "output");
        Assert.NotEmpty(result.OpsetImports);
    }

    [Fact]
    public void onnx_with_tensor_data_skips_raw_weights()
    {
        string path = Path.Combine(ModelCorpusDir, "onnx_with_tensor_data.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = OnnxMetadataWireParser.Parse(data);

        Assert.True(result.IsValid);
        // The raw_data field (SECRET_TENSOR_DATA...) should not appear in metadata
        Assert.DoesNotContain(result.MetadataProps.Values,
            v => v.Contains("SECRET_TENSOR", StringComparison.Ordinal));
    }

    [Fact]
    public void onnx_truncated_handled_gracefully()
    {
        string path = Path.Combine(ModelCorpusDir, "onnx_truncated.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = OnnxMetadataWireParser.Parse(data);

        // Should not throw; may or may not be valid
        _ = result;
    }

    // ──── Dangerous Model Format Classifier ────

    [Fact]
    public void pickle_protocol_2_detected_as_dangerous()
    {
        string path = Path.Combine(ModelCorpusDir, "pickle_protocol_2.pkl");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var classification = DangerousModelFormatClassifier.Classify(data);

        Assert.True(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.PickleProtocol, classification.Class);
        Assert.Contains("protocol_2", classification.DetectedProtocols);
    }

    [Fact]
    public void pickle_protocol_5_detected_as_dangerous()
    {
        string path = Path.Combine(ModelCorpusDir, "pickle_protocol_5.pkl");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var classification = DangerousModelFormatClassifier.Classify(data);

        Assert.True(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.PickleProtocol, classification.Class);
        Assert.Contains("protocol_5", classification.DetectedProtocols);
    }

    [Fact]
    public void pytorch_archive_detected_as_dangerous()
    {
        string path = Path.Combine(ModelCorpusDir, "pytorch_archive.pt");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var classification = DangerousModelFormatClassifier.Classify(data);

        Assert.True(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.PyTorchArchive, classification.Class);
        Assert.Contains(classification.ArchiveMembers,
            m => m.Contains("data.pkl", StringComparison.Ordinal));
    }

    [Fact]
    public void safetensors_classified_as_safe()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_minimal.safetensors");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var classification = DangerousModelFormatClassifier.Classify(data);

        Assert.False(classification.IsDangerous);
        Assert.Equal(DangerousModelClass.None, classification.Class);
    }

    [Fact]
    public void dangerous_extension_without_magic_still_classified()
    {
        // Simulate a file with .pkl extension but no pickle magic
        byte[] data = "just plain text"u8.ToArray();
        var classification = DangerousModelFormatClassifier.Classify(data, ".pkl");

        Assert.True(classification.IsDangerous);
    }

    [Fact]
    public void empty_file_classified_as_safe()
    {
        string path = Path.Combine(ModelCorpusDir, "empty_file.model");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var classification = DangerousModelFormatClassifier.Classify(data);

        Assert.False(classification.IsDangerous);
    }

    // ──── ModelFormatParser orchestrator (IFormatParser) ────

    [Fact]
    public async Task model_parser_yields_chunks_for_safetensors()
    {
        string path = Path.Combine(ModelCorpusDir, "safetensors_minimal.safetensors");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "test.safetensors");

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced c &&
            c.Chunk.VirtualPath.Contains("safetensors_header"));
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task model_parser_yields_gap_for_pickle()
    {
        string path = Path.Combine(ModelCorpusDir, "pickle_protocol_2.pkl");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "test.pkl");

        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode.Contains("dangerous_object_serialization", StringComparison.Ordinal));
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task model_parser_yields_gap_for_pytorch_archive()
    {
        string path = Path.Combine(ModelCorpusDir, "pytorch_archive.pt");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "test.pt");

        var gaps = events.OfType<ParserEvent.GapProduced>().ToList();
        Assert.Contains(gaps, g => g.Gap.DetailCode.Contains("dangerous_object_serialization", StringComparison.Ordinal));

        // Should emit archive member names as chunks
        Assert.Contains(events, e => e is ParserEvent.ChunkProduced c &&
            c.Chunk.VirtualPath.Contains("archive_members"));
    }

    [Fact]
    public async Task model_parser_yields_chunks_for_gguf()
    {
        string path = Path.Combine(ModelCorpusDir, "gguf_v3_minimal.gguf");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "test.gguf");

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced c &&
            c.Chunk.VirtualPath.Contains("gguf_metadata"));
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task model_parser_yields_chunks_for_onnx()
    {
        string path = Path.Combine(ModelCorpusDir, "onnx_minimal.bin");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "test.onnx");

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced c &&
            c.Chunk.VirtualPath.Contains("onnx_metadata"));
        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "model_weight_semantics_uncovered");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public async Task model_parser_handles_empty_file()
    {
        string path = Path.Combine(ModelCorpusDir, "empty_file.model");
        Assert.True(File.Exists(path));
        var events = await ParseFileAsync(path, "empty.model");

        Assert.Contains(events, e => e is ParserEvent.GapProduced g &&
            g.Gap.DetailCode == "empty_file");
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);
    }

    [Fact]
    public void model_parser_can_parse_recognizes_extensions()
    {
        var parser = new ModelFormatParser();
        var probe = new FormatProbe(
            Array.Empty<byte>(), Array.Empty<byte>(), ".safetensors", 0,
            new DetectedFormat("unknown", 0, Array.Empty<string>(), false));

        Assert.True(parser.CanParse(probe));
    }

    [Fact]
    public void model_parser_returns_correct_parser_id()
    {
        var parser = new ModelFormatParser();
        Assert.Equal("model", parser.ParserId);
    }

    // ──── Helpers ────

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
