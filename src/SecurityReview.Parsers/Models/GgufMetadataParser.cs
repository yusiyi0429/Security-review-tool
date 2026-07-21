using System.Text;

namespace SecurityReview.Parsers.Models;

/// <summary>
/// Statically inspects a GGUF file. Validates magic and version, bounds
/// tensor/KV counts to 1,000,000, strings to 1 MiB, uses checked offsets
/// and alignment. Emits key/value metadata and tensor names only.
/// </summary>
public static class GgufMetadataParser
{
    /// <summary>Maximum tensor count.</summary>
    public const ulong MaxTensorCount = 1_000_000;

    /// <summary>Maximum KV entry count.</summary>
    public const ulong MaxKvCount = 1_000_000;

    /// <summary>Maximum string length in bytes (1 MiB).</summary>
    public const long MaxStringLength = 1 * 1024 * 1024; // 1 MiB

    /// <summary>GGUF alignment.</summary>
    public const int Alignment = 32;

    /// <summary>GGUF magic bytes.</summary>
    public static ReadOnlySpan<byte> Magic => "GGUF"u8;

    /// <summary>Parse a GGUF file from a byte span. Never throws on malformed input.</summary>
    public static GgufMetadataResult Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 24)
            return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "too_short_for_header");

        if (!data[..4].SequenceEqual(Magic))
            return GgufMetadataResult.Failure(GgufFailureReason.InvalidMagic, "magic_mismatch");

        int pos = 4;
        uint version = ReadU32(data, ref pos);

        if (version is not 2 and not 3)
            return GgufMetadataResult.Failure(GgufFailureReason.UnsupportedVersion, $"version_{version}");
        if (pos + 16 > data.Length)
            return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "truncated_counts");

        ulong tensorCount = ReadU64(data, ref pos);
        ulong kvCount = ReadU64(data, ref pos);

        if (tensorCount > MaxTensorCount)
            return GgufMetadataResult.Failure(GgufFailureReason.ExcessiveTensorCount, $"tensors_{tensorCount}");
        if (kvCount > MaxKvCount)
            return GgufMetadataResult.Failure(GgufFailureReason.ExcessiveKvCount, $"kv_{kvCount}");

        var entries = new List<GgufMetadataEntry>();

        // Read KV pairs
        for (ulong i = 0; i < kvCount; i++)
        {
            if (pos + 8 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_key_len_truncated");

            long keyLen = ReadI64(data, ref pos);
            if (keyLen < 0 || keyLen > MaxStringLength)
                return GgufMetadataResult.Failure(GgufFailureReason.OversizedString, $"kv_key_len_{keyLen}");
            if (pos + keyLen > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_key_truncated");

            string key;
            try
            {
                key = Encoding.UTF8.GetString(data.Slice(pos, (int)keyLen));
            }
            catch (ArgumentException)
            {
                return GgufMetadataResult.Failure(GgufFailureReason.InvalidString, "kv_key_invalid_utf8");
            }

            pos += (int)keyLen;

            if (pos + 4 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_type_truncated");

            uint valueType = ReadU32(data, ref pos);
            string typeName = MapGgufType(valueType);
            string? stringVal = null;
            long? intVal = null;
            double? floatVal = null;

            switch (valueType)
            {
                case 8: // BOOL
                    if (pos + 1 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_bool_truncated");
                    intVal = data[pos];
                    pos += 1;
                    // Pad to 8 (for alignment in v3? skip padding)
                    // GGUF aligns variable-length values. Skip to next alignment boundary.
                    pos = AlignUp(pos, 1);
                    break;
                case 1: // UINT8
                case 2: // INT8
                    if (pos + 1 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_u8_truncated");
                    intVal = (sbyte)data[pos];
                    pos += 1;
                    pos = AlignUp(pos, 1);
                    break;
                case 3: // UINT16
                case 4: // INT16
                    if (pos + 2 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_u16_truncated");
                    intVal = (valueType == 4 ? (long)(short)ReadRawU16(data, ref pos) : ReadRawU16(data, ref pos));
                    break;
                case 5: // UINT32
                case 6: // INT32
                    if (pos + 4 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_u32_truncated");
                    intVal = (valueType == 6 ? ReadI32(data, ref pos) : ReadRawU32(data, ref pos));
                    break;
                case 7: // FLOAT32
                    if (pos + 4 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_f32_truncated");
                    floatVal = (double)ReadF32(data, ref pos);
                    break;
                case 11: // UINT64
                case 12: // INT64
                    if (pos + 8 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_u64_truncated");
                    intVal = (valueType == 12 ? (long)ReadRawU64(data, ref pos) : ReadI64(data, ref pos));
                    break;
                case 13: // FLOAT64
                    if (pos + 8 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_f64_truncated");
                    floatVal = ReadF64(data, ref pos);
                    break;
                case 9: // STRING
                    if (pos + 8 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_string_len_truncated");
                    long strLen = ReadI64(data, ref pos);
                    if (strLen < 0 || strLen > MaxStringLength)
                        return GgufMetadataResult.Failure(GgufFailureReason.OversizedString, $"kv_string_len_{strLen}");
                    if (pos + strLen > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_string_truncated");
                    try
                    {
                        stringVal = strLen == 0
                            ? string.Empty
                            : Encoding.UTF8.GetString(data.Slice(pos, (int)strLen));
                    }
                    catch (ArgumentException)
                    {
                        return GgufMetadataResult.Failure(GgufFailureReason.InvalidString, "kv_string_invalid_utf8");
                    }

                    pos += (int)strLen;
                    break;
                case 10: // ARRAY
                    // Array: uint32 type, uint64 length, then elements
                    if (pos + 4 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_array_type_truncated");
                    uint arrType = ReadU32(data, ref pos);
                    if (pos + 8 > data.Length)
                        return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_array_len_truncated");
                    long arrLen = ReadI64(data, ref pos);
                    if (arrLen < 0 || arrLen > (long)MaxKvCount)
                        return GgufMetadataResult.Failure(GgufFailureReason.ExcessiveKvCount, $"arr_len_{arrLen}");
                    // Skip array elements
                    int elemSize = GgufTypeSize(arrType);
                    if (elemSize == 0)
                    {
                        stringVal = "[array:unreadable]";
                    }
                    else
                    {
                        long skipBytes = arrLen * elemSize;
                        if (pos + skipBytes > data.Length)
                            return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "kv_array_truncated");
                        stringVal = $"[array:{MapGgufType(arrType)}:{arrLen}]";
                        pos += (int)skipBytes;
                    }

                    break;
                default:
                    return GgufMetadataResult.Failure(GgufFailureReason.InvalidMagic, $"kv_unknown_type_{valueType}");
            }

            entries.Add(new GgufMetadataEntry(key, typeName, stringVal, intVal, floatVal));
        }

        // Read tensor infos (v3 only has shape; v2 has more)
        var tensors = new List<GgufTensorInfo>();
        for (ulong i = 0; i < tensorCount; i++)
        {
            if (pos + 8 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_name_len_truncated");

            long nameLen = ReadI64(data, ref pos);
            if (nameLen < 0 || nameLen > MaxStringLength)
                return GgufMetadataResult.Failure(GgufFailureReason.OversizedString, $"tensor_name_len_{nameLen}");
            if (pos + nameLen > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_name_truncated");

            string name;
            try
            {
                name = Encoding.UTF8.GetString(data.Slice(pos, (int)nameLen));
            }
            catch (ArgumentException)
            {
                return GgufMetadataResult.Failure(GgufFailureReason.InvalidString, "tensor_name_invalid_utf8");
            }

            pos += (int)nameLen;

            if (pos + 4 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_ndims_truncated");

            uint nDims = ReadU32(data, ref pos);
            if (nDims > 16) // practical safety cap
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, $"tensor_ndims_{nDims}");

            var shapeList = new List<long>();
            if (pos + (long)nDims * 8 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_shape_truncated");
            for (uint j = 0; j < nDims; j++)
            {
                shapeList.Add(ReadI64(data, ref pos));
            }

            if (pos + 4 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_type_truncated");
            uint tensorType = ReadU32(data, ref pos);
            string typeStr = MapGgufType(tensorType);

            if (pos + 8 > data.Length)
                return GgufMetadataResult.Failure(GgufFailureReason.Truncated, "tensor_offset_truncated");
            long offset = ReadI64(data, ref pos);

            tensors.Add(new GgufTensorInfo(name, (int)nDims, shapeList, typeStr, offset));
        }

        return new GgufMetadataResult(true, version,
            entries.AsReadOnly(), tensors.AsReadOnly(),
            GgufFailureReason.None, null);
    }

    private static string MapGgufType(uint valueType) => valueType switch
    {
        1 => "U8",
        2 => "I8",
        3 => "U16",
        4 => "I16",
        5 => "U32",
        6 => "I32",
        7 => "F32",
        8 => "BOOL",
        9 => "STRING",
        10 => "ARRAY",
        11 => "U64",
        12 => "I64",
        13 => "F64",
        _ => $"UNKNOWN_{valueType}",
    };

    private static int GgufTypeSize(uint t) => t switch
    {
        1 or 2 or 8 => 1,
        3 or 4 => 2,
        5 or 6 or 7 => 4,
        11 or 12 or 13 => 8,
        _ => 0,
    };

    private static int AlignUp(int value, int alignment) =>
        alignment == 0 ? value : ((value + alignment - 1) / alignment) * alignment;

    private static uint ReadU32(ReadOnlySpan<byte> data, ref int pos)
    {
        uint val = (uint)(data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24));
        pos += 4;
        return val;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> data, ref int pos)
    {
        ulong val = (ulong)data[pos]
                  | ((ulong)data[pos + 1] << 8)
                  | ((ulong)data[pos + 2] << 16)
                  | ((ulong)data[pos + 3] << 24)
                  | ((ulong)data[pos + 4] << 32)
                  | ((ulong)data[pos + 5] << 40)
                  | ((ulong)data[pos + 6] << 48)
                  | ((ulong)data[pos + 7] << 56);
        pos += 8;
        return val;
    }

    private static long ReadI64(ReadOnlySpan<byte> data, ref int pos)
    {
        return (long)ReadU64(data, ref pos);
    }

    private static int ReadI32(ReadOnlySpan<byte> data, ref int pos)
    {
        return (int)ReadU32(data, ref pos);
    }

    private static long ReadRawU32(ReadOnlySpan<byte> data, ref int pos)
    {
        uint val = ReadU32(data, ref pos);
        return val;
    }

    private static ushort ReadRawU16(ReadOnlySpan<byte> data, ref int pos)
    {
        ushort val = (ushort)(data[pos] | (data[pos + 1] << 8));
        pos += 2;
        return val;
    }

    private static ulong ReadRawU64(ReadOnlySpan<byte> data, ref int pos)
    {
        return ReadU64(data, ref pos);
    }

    private static float ReadF32(ReadOnlySpan<byte> data, ref int pos)
    {
        uint bits = ReadU32(data, ref pos);
        return BitConverter.Int32BitsToSingle((int)bits);
    }

    private static double ReadF64(ReadOnlySpan<byte> data, ref int pos)
    {
        return BitConverter.Int64BitsToDouble((long)ReadU64(data, ref pos));
    }
}
