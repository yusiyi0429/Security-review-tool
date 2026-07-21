using System.Text;
using System.Text.Json;

namespace SecurityReview.Parsers.Models;

/// <summary>
/// Statically inspects a safetensors file. Reads the little-endian 64-bit
/// JSON header length, validates bounds (2–100 MiB), stream-parses JSON
/// tensor names/dtypes/shapes/metadata. Never reads tensor payload beyond
/// generic string content when enabled by policy.
/// </summary>
public static class SafeTensorsHeaderParser
{
    /// <summary>Minimum header length (2 bytes — at least an empty JSON object).</summary>
    public const long MinHeaderLength = 2;

    /// <summary>Maximum header length (100 MiB).</summary>
    public const long MaxHeaderLength = 100 * 1024 * 1024; // 100 MiB

    /// <summary>
    /// Parse a safetensors file from a byte span. The parser never throws
    /// on malformed input.
    /// </summary>
    public static SafeTensorsHeaderResult Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.Truncated, "data_short");

        long headerLen = ReadLittleEndianU64(data, 0);

        if (headerLen < MinHeaderLength)
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.HeaderTooSmall,
                $"header_len_{headerLen}");
        if (headerLen > MaxHeaderLength)
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.HeaderTooLarge,
                $"header_len_{headerLen}");

        int headerOffset = 8;
        long headerEnd;
        try
        {
            headerEnd = checked(headerOffset + headerLen);
        }
        catch (OverflowException)
        {
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.HeaderTooLarge, "overflow");
        }

        if (headerEnd > data.Length)
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.Truncated,
                $"header_past_eof_{headerEnd}_{data.Length}");

        var headerSpan = data.Slice(headerOffset, (int)headerLen);

        // Parse JSON header
        JsonDocument doc;
        try
        {
            var headerBytes = headerSpan.ToArray();
            doc = JsonDocument.Parse(headerBytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                MaxDepth = 256,
            });
        }
        catch (JsonException ex)
        {
            return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.InvalidJson,
                $"json_parse: {ex.Message}");
        }

        using (doc)
        {
            var tensors = new List<SafeTensorEntry>();
            var metadata = new Dictionary<string, string>();
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
                return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.InvalidJson, "root_not_object");

            // Compute total tensor payload size
            long totalPayloadSize = 0;

            foreach (var property in root.EnumerateObject())
            {
                if (property.NameEquals("__metadata__"))
                {
                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var metaProp in property.Value.EnumerateObject())
                        {
                            string? val = metaProp.Value.GetString();
                            if (val != null)
                                metadata[metaProp.Name] = val;
                        }
                    }
                }
                else
                {
                    // Tensor entry
                    if (property.Value.ValueKind != JsonValueKind.Object)
                        continue;

                    string name = property.Name;
                    string dtype = "UNKNOWN";
                    var shape = new List<long>();
                    long dataStart = 0;
                    long dataEnd = 0;

                    if (property.Value.TryGetProperty("dtype", out var dtypeEl))
                        dtype = dtypeEl.GetString() ?? "UNKNOWN";

                    if (property.Value.TryGetProperty("shape", out var shapeEl) &&
                        shapeEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var dim in shapeEl.EnumerateArray())
                        {
                            if (dim.TryGetInt64(out long d))
                                shape.Add(d);
                        }
                    }

                    if (property.Value.TryGetProperty("data_offsets", out var offsetsEl) &&
                        offsetsEl.ValueKind == JsonValueKind.Array)
                    {
                        var offsets = offsetsEl.EnumerateArray().ToList();
                        if (offsets.Count >= 2)
                        {
                            if (offsets[0].TryGetInt64(out long s))
                                dataStart = s;
                            if (offsets[1].TryGetInt64(out long e))
                                dataEnd = e;
                        }
                    }

                    if (dataEnd > dataStart)
                        totalPayloadSize = Math.Max(totalPayloadSize, dataEnd);

                    tensors.Add(new SafeTensorEntry(name, dtype, shape, dataStart, dataEnd));
                }
            }

            if (tensors.Count == 0 && metadata.Count == 0)
                return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.MissingTensorInfo,
                    "no_tensors_or_metadata");

            long totalFileLen = 8 + headerLen + totalPayloadSize;
            if (totalFileLen > data.Length)
                return SafeTensorsHeaderResult.Failure(SafeTensorsFailureReason.FileLengthMismatch,
                    $"expected_{totalFileLen}_got_{data.Length}");

            return new SafeTensorsHeaderResult(true, tensors.AsReadOnly(),
                new Dictionary<string, string>(metadata),
                SafeTensorsFailureReason.None, null, headerLen, data.Length);
        }
    }

    private static long ReadLittleEndianU64(ReadOnlySpan<byte> data, int offset)
    {
        if (offset + 8 > data.Length) return 0;
        return (long)data[offset]
             | ((long)data[offset + 1] << 8)
             | ((long)data[offset + 2] << 16)
             | ((long)data[offset + 3] << 24)
             | ((long)data[offset + 4] << 32)
             | ((long)data[offset + 5] << 40)
             | ((long)data[offset + 6] << 48)
             | ((long)data[offset + 7] << 56);
    }
}
