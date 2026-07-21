using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Models;

/// <summary>
/// Orchestrates safe model metadata extraction. Detects safetensors, GGUF,
/// ONNX, and pickle/PyTorch formats. Produces metadata chunks, child-discovered
/// events, and coverage gaps for dangerous or unparseable regions.
/// </summary>
public sealed class ModelFormatParser : IFormatParser
{
    public string ParserId => "model";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId is "model" or "safetensors" or "gguf" or "onnx"
               || IsModelExtension(probe.ExtensionHint);
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input,
        ParseContext context,
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
                new ParserEvent.ParseCompleted()
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input,
        ParseContext context,
        CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream stream = input.Stream;
        stream.Position = 0;

        // Read full content into memory (model files are bounded)
        byte[] data;
        try
        {
            long length = Math.Min(input.DeclaredLength, 1024L * 1024 * 1024); // 1 GiB cap
            if (length > int.MaxValue)
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "model",
                    "model_read", GapReason.ParserMemory, "file_too_large",
                    length, null, DateTimeOffset.UtcNow)));
                events.Add(new ParserEvent.ParseCompleted());
                return events;
            }

            data = new byte[(int)length];
            int totalRead = 0;
            while (totalRead < data.Length)
            {
                int n = await stream.ReadAsync(data.AsMemory(totalRead, data.Length - totalRead),
                    cancellationToken).ConfigureAwait(false);
                if (n == 0) break;
                totalRead += n;
            }

            if (totalRead < data.Length)
                data = data.AsSpan(0, totalRead).ToArray();
        }
        catch (EndOfStreamException)
        {
            data = Array.Empty<byte>();
        }

        if (data.Length == 0)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "model",
                "model_parse", GapReason.Corrupt, "empty_file",
                null, null, DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        var span = new ReadOnlySpan<byte>(data);

        // Determine format by probing magic bytes
        string? formatId = ModelFormatSniffer.DetectFormat(span);
        string? extensionHint = ExtractExtensionHint(context.VirtualPath);

        // Step 1: Dangerous format classification (always check first)
        var dangerClass = DangerousModelFormatClassifier.Classify(span, extensionHint);
        if (dangerClass.IsDangerous)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                "model", "model_classify", GapReason.UnsupportedFormat,
                FormattableString.Invariant($"dangerous_object_serialization_not_loaded: {dangerClass.Class}, {dangerClass.Detail}"),
                data.Length, null, DateTimeOffset.UtcNow)));

            // Emit archive member names as safe metadata
            if (dangerClass.ArchiveMembers.Count > 0)
            {
                var sb = new StringBuilder();
                sb.AppendLine(CultureInfo.InvariantCulture, $"archive_members:");
                foreach (var m in dangerClass.ArchiveMembers)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"  {m}");
                events.Add(MakeChunk(context, "archive_members", sb.ToString(), 0, sb.Length));
            }

            if (dangerClass.DetectedProtocols.Count > 0)
            {
                var sb = new StringBuilder();
                sb.AppendLine(CultureInfo.InvariantCulture, $"detected_protocols:");
                foreach (var p in dangerClass.DetectedProtocols)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"  {p}");
                events.Add(MakeChunk(context, "detected_protocols", sb.ToString(), 0, sb.Length));
            }

            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Step 2: Parse safe formats
        switch (formatId)
        {
            case "safetensors":
            {
                var result = SafeTensorsHeaderParser.Parse(span);
                if (result.IsValid)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine(CultureInfo.InvariantCulture, $"header_length: {result.HeaderLength}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"total_file_length: {result.TotalFileLength}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"tensor_count: {result.Tensors.Count}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"tensors:");
                    foreach (var t in result.Tensors)
                        sb.AppendLine(CultureInfo.InvariantCulture,
                            $"  {t.Name}: dtype={t.Dtype} shape=[{string.Join(",", t.Shape)}] offsets=[{t.DataOffsetStart},{t.DataOffsetEnd}]");
                    if (result.Metadata.Count > 0)
                    {
                        sb.AppendLine(CultureInfo.InvariantCulture, $"metadata:");
                        foreach (var kvp in result.Metadata)
                            sb.AppendLine(CultureInfo.InvariantCulture, $"  {kvp.Key}: {kvp.Value}");
                    }

                    events.Add(MakeChunk(context, "safetensors_header", sb.ToString(), 0, (int)result.TotalFileLength));

                    // Emit gap for weight data
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "safetensors",
                        "model_weights", GapReason.UnsupportedRegion,
                        "model_weight_semantics_uncovered",
                        result.TotalFileLength - 8 - result.HeaderLength, null,
                        DateTimeOffset.UtcNow)));
                }
                else
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "safetensors",
                        "model_parse", GapReason.Corrupt,
                        FormattableString.Invariant($"{result.FailureReason}: {result.FailureDetail}"),
                        data.Length, null, DateTimeOffset.UtcNow)));
                }

                break;
            }
            case "gguf":
            {
                var result = GgufMetadataParser.Parse(span);
                if (result.IsValid)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine(CultureInfo.InvariantCulture, $"version: {result.Version}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"kv_count: {result.Entries.Count}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"metadata:");
                    foreach (var e in result.Entries)
                    {
                        string val = e.StringValue ?? e.IntValue?.ToString(CultureInfo.InvariantCulture)
                            ?? e.FloatValue?.ToString(CultureInfo.InvariantCulture) ?? "(null)";
                        sb.AppendLine(CultureInfo.InvariantCulture, $"  {e.Key}: {val}");
                    }

                    sb.AppendLine(CultureInfo.InvariantCulture, $"tensor_count: {result.Tensors.Count}");
                    sb.AppendLine(CultureInfo.InvariantCulture, $"tensors:");
                    foreach (var t in result.Tensors)
                        sb.AppendLine(CultureInfo.InvariantCulture,
                            $"  {t.Name}: dtype={t.Dtype} ndims={t.NDims} shape=[{string.Join(",", t.Shape)}] offset={t.Offset}");

                    events.Add(MakeChunk(context, "gguf_metadata", sb.ToString(), 0, sb.Length));

                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "gguf",
                        "model_weights", GapReason.UnsupportedRegion,
                        "model_weight_semantics_uncovered",
                        data.Length, null, DateTimeOffset.UtcNow)));
                }
                else
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "gguf",
                        "model_parse", GapReason.Corrupt,
                        FormattableString.Invariant($"{result.FailureReason}: {result.FailureDetail}"),
                        data.Length, null, DateTimeOffset.UtcNow)));
                }

                break;
            }
            case "onnx":
            {
                var result = OnnxMetadataWireParser.Parse(span);
                if (result.IsValid)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine(CultureInfo.InvariantCulture, $"ir_version: {result.IrVersion}");
                    if (result.ProducerName != null)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"producer: {result.ProducerName}");
                    if (result.ProducerVersion != null)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"producer_version: {result.ProducerVersion}");
                    if (result.Domain != null)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"domain: {result.Domain}");
                    if (result.DocString != null)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"doc_string: {result.DocString}");
                    if (result.GraphNames.Count > 0)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"graph_names: [{string.Join(",", result.GraphNames)}]");
                    if (result.NodeNames.Count > 0)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"node_names: [{string.Join(",", result.NodeNames)}]");
                    if (result.InputNames.Count > 0)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"input_names: [{string.Join(",", result.InputNames)}]");
                    if (result.OutputNames.Count > 0)
                        sb.AppendLine(CultureInfo.InvariantCulture, $"output_names: [{string.Join(",", result.OutputNames)}]");
                    if (result.MetadataProps.Count > 0)
                    {
                        sb.AppendLine(CultureInfo.InvariantCulture, $"metadata_props:");
                        foreach (var kvp in result.MetadataProps)
                            sb.AppendLine(CultureInfo.InvariantCulture, $"  {kvp.Key}: {kvp.Value}");
                    }

                    if (result.OpsetImports.Count > 0)
                    {
                        sb.AppendLine(CultureInfo.InvariantCulture, $"opset_imports:");
                        foreach (var (d, v) in result.OpsetImports)
                            sb.AppendLine(CultureInfo.InvariantCulture, $"  domain={d} version={v}");
                    }

                    events.Add(MakeChunk(context, "onnx_metadata", sb.ToString(), 0, sb.Length));

                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "onnx",
                        "model_weights", GapReason.UnsupportedRegion,
                        "model_weight_semantics_uncovered",
                        data.Length - result.BytesConsumed, null,
                        DateTimeOffset.UtcNow)));
                }
                else
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "onnx",
                        "model_parse", GapReason.Corrupt,
                        FormattableString.Invariant($"{result.FailureReason}: {result.FailureDetail}"),
                        data.Length, null, DateTimeOffset.UtcNow)));
                }

                break;
            }
            default:
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "model",
                    "model_parse", GapReason.UnsupportedFormat,
                    FormattableString.Invariant($"unknown_model_format: {ModelFormatSniffer.DescribeFormat(span)}"),
                    data.Length, null, DateTimeOffset.UtcNow)));
                break;
            }
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static ParserEvent.ChunkProduced MakeChunk(ParseContext context,
        string tag, string text, long sourceStart, long sourceLength)
    {
        var chunk = new ContentChunk(
            ProtocolVersion: 1,
            JobId: context.JobId,
            Sequence: 0,
            VirtualPath: $"{context.VirtualPath}/{tag}",
            FormatId: "model",
            ContentKind: ContentKind.Metadata,
            Encoding: "utf-8",
            Text: text,
            SourceStart: sourceStart,
            SourceLength: sourceLength,
            LocationMap: Array.Empty<LocationMapEntry>(),
            IsFinal: false);
        return new ParserEvent.ChunkProduced(chunk);
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "model",
            "model_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    private static string? ExtractExtensionHint(string virtualPath)
    {
        if (string.IsNullOrEmpty(virtualPath)) return null;
        return Path.GetExtension(virtualPath)?.ToLowerInvariant();
    }

    private static bool IsModelExtension(string? ext)
    {
        if (ext == null) return false;
        return ext switch
        {
            ".safetensors" or ".gguf" or ".onnx" or ".pt" or ".pth" or ".pkl" or ".pickle" or ".model"
                => true,
            _ => false,
        };
    }
}

/// <summary>
/// Detects model format from magic bytes (separate from FormatSniffer).
/// </summary>
internal static class ModelFormatSniffer
{
    public static string DetectFormat(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return "unknown";

        // Safetensors: starts with 8-byte LE u64 header length. Most valid
        // safetensors have header length small enough that top 4 bytes are 0.
        if (data.Length >= 8)
        {
            // Check if the upper 32 bits are zero (small header length, LE)
            bool upper32Zero = data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0;
            if (upper32Zero && data[0] != 0) // first byte not 0 = some header length > 0
            {
                // More specific check: try to see if it starts with '{'
                long headerLen = (long)data[0] | ((long)data[1] << 8)
                    | ((long)data[2] << 16) | ((long)data[3] << 24);
                if (headerLen is >= 2 and <= 100 * 1024 * 1024
                    && data.Length > 8 + headerLen
                    && data[8] == (byte)'{')
                    return "safetensors";
            }
        }

        // GGUF magic
        if (data.Length >= 4 && data[0] == (byte)'G' && data[1] == (byte)'G' &&
            data[2] == (byte)'U' && data[3] == (byte)'F')
            return "gguf";

        // ONNX: starts with protobuf varint tag for ir_version (field 1, varint = 0x08)
        // followed by a valid ir_version value (1-10)
        if (data.Length >= 2 && data[0] == 0x08 && data[1] >= 1 && data[1] <= 10)
            return "onnx";

        return "unknown";
    }

    public static string DescribeFormat(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 8)
        {
            bool upper32Zero = data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0;
            if (upper32Zero)
                return "possible_safetensors";

            if (data[0] == (byte)'G' && data[1] == (byte)'G' &&
                data[2] == (byte)'U' && data[3] == (byte)'F')
                return "gguf_magic_mismatch";
        }

        return "binary_unknown";
    }
}
