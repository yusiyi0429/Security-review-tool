using System.Text;

namespace SecurityReview.Parsers.Models;

/// <summary>
/// Bounded protobuf wire walker for ONNX ModelProto files. Extracts metadata
/// fields (producer, domain, doc string, metadata props, graph/node/input/output
/// names). Skips tensor raw_data by validated length. Does NOT instantiate an
/// ONNX runtime.
/// </summary>
public static class OnnxMetadataWireParser
{
    /// <summary>Maximum message size allowed (1 GiB, conservative bound).</summary>
    public const long MaxMessageSize = 1L * 1024 * 1024 * 1024;

    // Protobuf wire type constants
    private const int WireVarint = 0;
    private const int Wire64Bit = 1;
    private const int WireLengthDelimited = 2;
    private const int Wire32Bit = 5;

    /// <summary>Parse ONNX model metadata from a byte span. Never throws.</summary>
    public static OnnxMetadataResult Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return OnnxMetadataResult.Failure(OnnxFailureReason.Truncated, "empty_data");

        int pos = 0;
        long irVersion = 0;
        string? producerName = null;
        string? producerVersion = null;
        string? domain = null;
        string? docString = null;
        var metadataProps = new Dictionary<string, string>();
        var opsetImports = new List<(string, long)>();
        var graphNames = new List<string>();
        var nodeNames = new List<string>();
        var inputNames = new List<string>();
        var outputNames = new List<string>();

        while (pos < data.Length)
        {
            if (!TryReadTag(data, ref pos, out int fieldNum, out int wireType))
                return OnnxMetadataResult.Failure(OnnxFailureReason.InvalidVarint, "tag_truncated");

            switch (fieldNum)
            {
                case 1: // ir_version
                    if (wireType == WireVarint)
                    {
                        if (!TryReadVarint(data, ref pos, out long ver))
                            return OnnxMetadataResult.Failure(OnnxFailureReason.InvalidVarint, "ir_version_truncated");
                        irVersion = ver;
                    }
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 6: // doc_string
                    if (wireType == WireLengthDelimited)
                        docString = ReadWireString(data, ref pos);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 7: // producer_name
                    if (wireType == WireLengthDelimited)
                        producerName = ReadWireString(data, ref pos);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 8: // producer_version
                    if (wireType == WireLengthDelimited)
                        producerVersion = ReadWireString(data, ref pos);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 9: // domain
                    if (wireType == WireLengthDelimited)
                        domain = ReadWireString(data, ref pos);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 14: // metadata_props (StringStringEntryProto: key=1, value=2)
                    if (wireType == WireLengthDelimited)
                        ReadMetadataProp(data, ref pos, metadataProps);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 11: // opset_import (OperatorSetIdProto: domain=1, version=2)
                    if (wireType == WireLengthDelimited)
                        ReadOpsetImport(data, ref pos, opsetImports);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                case 10: // graph (GraphProto)
                    if (wireType == WireLengthDelimited)
                        ReadGraph(data, ref pos, graphNames, nodeNames, inputNames, outputNames);
                    else SkipWireValue(data, ref pos, wireType);
                    break;
                default:
                    SkipWireValue(data, ref pos, wireType);
                    break;
            }
        }

        return new OnnxMetadataResult(true, irVersion,
            producerName, producerVersion, domain, docString,
            graphNames.AsReadOnly(), nodeNames.AsReadOnly(),
            inputNames.AsReadOnly(), outputNames.AsReadOnly(),
            new Dictionary<string, string>(metadataProps),
            opsetImports.AsReadOnly(),
            OnnxFailureReason.None, null, pos);
    }

    private static void ReadGraph(ReadOnlySpan<byte> data, ref int pos,
        List<string> graphNames, List<string> nodeNames,
        List<string> inputNames, List<string> outputNames)
    {
        if (!TryReadLenPrefix(data, ref pos, out int subStart, out int subEnd))
            return;
        while (subStart < subEnd)
        {
            if (!TryReadTag(data, ref subStart, out int fieldNum, out int wireType))
                return;
            switch (fieldNum)
            {
                case 1: // name
                    if (wireType == WireLengthDelimited)
                        graphNames.Add(ReadWireString(data, ref subStart) ?? string.Empty);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 2: // node (NodeProto)
                    if (wireType == WireLengthDelimited)
                        ReadNode(data, ref subStart, nodeNames);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 4: // input (ValueInfoProto)
                    if (wireType == WireLengthDelimited)
                        inputNames.Add(ReadValueInfoName(data, ref subStart) ?? string.Empty);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 5: // output (ValueInfoProto)
                    if (wireType == WireLengthDelimited)
                        outputNames.Add(ReadValueInfoName(data, ref subStart) ?? string.Empty);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 6: // initializer (TensorProto) — skip entirely
                default:
                    SkipWireValue(data, ref subStart, wireType);
                    break;
            }
        }
    }

    private static void ReadNode(ReadOnlySpan<byte> data, ref int pos, List<string> nodeNames)
    {
        if (!TryReadLenPrefix(data, ref pos, out int subStart, out int subEnd))
            return;
        while (subStart < subEnd)
        {
            if (!TryReadTag(data, ref subStart, out int fieldNum, out int wireType))
                return;
            switch (fieldNum)
            {
                case 3: // name
                    if (wireType == WireLengthDelimited)
                        nodeNames.Add(ReadWireString(data, ref subStart) ?? string.Empty);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                default:
                    SkipWireValue(data, ref subStart, wireType);
                    break;
            }
        }
    }

    private static string? ReadValueInfoName(ReadOnlySpan<byte> data, ref int pos)
    {
        if (!TryReadLenPrefix(data, ref pos, out int subStart, out int subEnd))
            return null;
        while (subStart < subEnd)
        {
            if (!TryReadTag(data, ref subStart, out int fieldNum, out int wireType))
                return null;
            if (fieldNum == 1 && wireType == WireLengthDelimited)
                return ReadWireString(data, ref subStart);
            SkipWireValue(data, ref subStart, wireType);
        }

        return null;
    }

    private static void ReadMetadataProp(ReadOnlySpan<byte> data, ref int pos,
        Dictionary<string, string> props)
    {
        if (!TryReadLenPrefix(data, ref pos, out int subStart, out int subEnd))
            return;
        string? key = null;
        string? value = null;
        while (subStart < subEnd)
        {
            if (!TryReadTag(data, ref subStart, out int fieldNum, out int wireType))
                return;
            switch (fieldNum)
            {
                case 1: // key
                    if (wireType == WireLengthDelimited)
                        key = ReadWireString(data, ref subStart);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 2: // value
                    if (wireType == WireLengthDelimited)
                        value = ReadWireString(data, ref subStart);
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                default:
                    SkipWireValue(data, ref subStart, wireType);
                    break;
            }
        }

        if (key != null)
            props[key] = value ?? string.Empty;
    }

    private static void ReadOpsetImport(ReadOnlySpan<byte> data, ref int pos,
        List<(string, long)> imports)
    {
        if (!TryReadLenPrefix(data, ref pos, out int subStart, out int subEnd))
            return;
        string domain = string.Empty;
        long version = 0;
        while (subStart < subEnd)
        {
            if (!TryReadTag(data, ref subStart, out int fieldNum, out int wireType))
                return;
            switch (fieldNum)
            {
                case 1: // domain
                    if (wireType == WireLengthDelimited)
                        domain = ReadWireString(data, ref subStart) ?? string.Empty;
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                case 2: // version
                    if (wireType == WireVarint)
                    {
                        if (TryReadVarint(data, ref subStart, out long ver))
                            version = ver;
                    }
                    else SkipWireValue(data, ref subStart, wireType);
                    break;
                default:
                    SkipWireValue(data, ref subStart, wireType);
                    break;
            }
        }

        imports.Add((domain, version));
    }

    private static string? ReadWireString(ReadOnlySpan<byte> data, ref int pos)
    {
        if (!TryReadLenPrefixBytes(data, ref pos, out int strStart, out int strLen))
            return null;
        if (strLen == 0) return string.Empty;
        if (strLen > int.MaxValue / 2) return null; // safety cap
        try
        {
            return Encoding.UTF8.GetString(data.Slice(strStart, strLen));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static bool TryReadLenPrefix(ReadOnlySpan<byte> data, ref int pos,
        out int subStart, out int subEnd)
    {
        if (!TryReadVarint(data, ref pos, out long length))
        {
            subStart = subEnd = 0;
            return false;
        }

        if (length < 0 || length > MaxMessageSize)
        {
            subStart = subEnd = 0;
            return false;
        }

        int start = pos;
        int end;
        try
        {
            end = checked(start + (int)length);
        }
        catch (OverflowException)
        {
            subStart = subEnd = 0;
            return false;
        }

        if (end > data.Length)
        {
            end = data.Length;
        }

        subStart = pos;
        subEnd = end;
        pos = end;
        return true;
    }

    private static bool TryReadLenPrefixBytes(ReadOnlySpan<byte> data, ref int pos,
        out int strStart, out int strLen)
    {
        if (!TryReadVarint(data, ref pos, out long length))
        {
            strStart = strLen = 0;
            return false;
        }

        if (length < 0 || length > MaxMessageSize)
        {
            strStart = strLen = 0;
            return false;
        }

        int len = (int)length;
        if (pos + len > data.Length)
        {
            strStart = strLen = 0;
            return false;
        }

        strStart = pos;
        strLen = len;
        pos += len;
        return true;
    }

    private static bool TryReadTag(ReadOnlySpan<byte> data, ref int pos,
        out int fieldNum, out int wireType)
    {
        if (!TryReadVarint(data, ref pos, out long tag))
        {
            fieldNum = wireType = 0;
            return false;
        }

        fieldNum = (int)(tag >> 3);
        wireType = (int)(tag & 0x07);
        return true;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int pos, out long value)
    {
        value = 0;
        int shift = 0;
        while (pos < data.Length)
        {
            byte b = data[pos++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift >= 64)
                return false;
        }

        return false; // unexpected end
    }

    private static void SkipWireValue(ReadOnlySpan<byte> data, ref int pos, int wireType)
    {
        switch (wireType)
        {
            case WireVarint:
                while (pos < data.Length && (data[pos++] & 0x80) != 0) { }
                break;
            case Wire64Bit:
                pos = Math.Min(pos + 8, data.Length);
                break;
            case WireLengthDelimited:
                if (TryReadVarint(data, ref pos, out long length))
                {
                    if (length > 0 && length < MaxMessageSize)
                        pos = Math.Min(pos + (int)length, data.Length);
                }

                break;
            case Wire32Bit:
                pos = Math.Min(pos + 4, data.Length);
                break;
        }
    }
}
