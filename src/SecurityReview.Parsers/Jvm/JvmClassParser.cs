namespace SecurityReview.Parsers.Jvm;

// JvmConstantTag carries the official JVMS §4.4 tag names — including
// type-name-like identifiers (Integer, Float, Long, Double, String). The
// analyzer rule CA1720 is suppressed here on purpose.
#pragma warning disable CA1720

/// <summary>
/// JVM class-file constant-pool tag. Values are taken verbatim from
/// <c>JVMS §4.4</c>.
/// </summary>
public enum JvmConstantTag
{
    Utf8 = 1,
    Integer = 3,
    Float = 4,
    Long = 5,
    Double = 6,
    Class = 7,
    String = 8,
    FieldRef = 9,
    MethodRef = 10,
    InterfaceMethodRef = 11,
    NameAndType = 12,
    MethodHandle = 15,
    MethodType = 16,
    Dynamic = 17,
    InvokeDynamic = 18,
    Module = 19,
    Package = 20,
}

#pragma warning restore CA1720

/// <summary>
/// A single constant-pool entry recorded by <see cref="JvmClassParser"/>.
/// </summary>
public sealed record JvmConstantEntry(
    int Index,
    JvmConstantTag Tag,
    long ByteOffset,
    string? Value,
    string? Name,
    string? Descriptor,
    string? ResolvedClassName,
    long? LongValue,
    double? DoubleValue,
    ushort? ClassNameIndex,
    ushort? NameIndex,
    ushort? DescriptorIndex,
    ushort? StringIndex);

/// <summary>
/// Reason why <see cref="JvmClassParser"/> rejected a class file.
/// </summary>
public enum JvmClassFailureReason
{
    None,
    InvalidMagic,
    UnsupportedVersion,
    Truncated,
    ConstantPoolOverflow,
    ConstantPoolEntryTooLarge,
    InvalidModifiedUtf8,
    UnknownPoolTag,
    InvalidPoolReference,
}

/// <summary>
/// Result of parsing a single .class file. Carries the resolved class name
/// (when available), the constant-pool entries we successfully decoded, and
/// a failure reason when parsing stopped early.
/// </summary>
public sealed record JvmClassResult(
    bool IsValid,
    string? ClassName,
    ushort MinorVersion,
    ushort MajorVersion,
    IReadOnlyList<JvmConstantEntry> ConstantPool,
    JvmClassFailureReason FailureReason,
    int? FailurePoolIndex,
    string? FailureDetail)
{
    public static JvmClassResult Failure(JvmClassFailureReason reason, string detail,
        int? poolIndex = null) =>
        new(false, null, 0, 0, Array.Empty<JvmConstantEntry>(), reason, poolIndex, detail);

    public static JvmClassResult Empty { get; } =
        new(true, null, 0, 0, Array.Empty<JvmConstantEntry>(),
            JvmClassFailureReason.None, null, null);
}

/// <summary>
/// Parses a JVM class file's constant pool using only the structural
/// fields required to extract strings, names, and class references.
/// Does not interpret bytecode, resolve referenced classes, load the JVM,
/// or decompile methods. Unknown or invalid constant-pool tags stop parsing
/// of the current class.
/// </summary>
public static class JvmClassParser
{
    /// <summary>Maximum accepted class major version (Java 25).</summary>
    public const ushort MaxMajorVersion = 69;

    /// <summary>Minimum accepted class major version (Java 1.0/1.1).</summary>
    public const ushort MinMajorVersion = 45;

    /// <summary>Maximum constant-pool entry count.</summary>
    public const int MaxPoolCount = 65_535;

    /// <summary>Maximum length of any single CONSTANT_Utf8 entry (1 MiB).</summary>
    public const int MaxUtf8Length = ModifiedUtf8Decoder.MaxUtf8Length;

    /// <summary>
    /// Parse <paramref name="data"/> as a JVM class file. The parser never
    /// throws on malformed input — instead it returns
    /// <see cref="JvmClassResult"/> with <see cref="JvmClassResult.IsValid"/>
    /// set to <c>false</c> and a populated <see cref="JvmClassResult.FailureReason"/>.
    /// </summary>
    public static JvmClassResult Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10)
            return JvmClassResult.Failure(JvmClassFailureReason.Truncated, "header_too_short");

        // Magic
        if (data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE)
            return JvmClassResult.Failure(JvmClassFailureReason.InvalidMagic, "magic_mismatch");

        var reader = new BigEndianReader(data);
        // skip magic
        reader.Skip(4);
        ushort minor;
        ushort major;
        ushort poolCount;
        try
        {
            minor = reader.ReadUInt16();
            major = reader.ReadUInt16();
            poolCount = reader.ReadUInt16();
        }
        catch (EndOfStreamException)
        {
            return JvmClassResult.Failure(JvmClassFailureReason.Truncated, "header_truncated");
        }

        if (major < MinMajorVersion || major > MaxMajorVersion)
            return JvmClassResult.Failure(JvmClassFailureReason.UnsupportedVersion,
                $"major_{major}");

        if (poolCount == 0 || poolCount > MaxPoolCount)
            return JvmClassResult.Failure(JvmClassFailureReason.ConstantPoolOverflow,
                $"pool_count_{poolCount}");

        var pool = new JvmConstantEntry[poolCount];
        var poolList = new List<JvmConstantEntry>(poolCount);
        // Slot 0 is reserved/unused; leave it empty but indexed.
        // For 1-based lookup we keep entries in a dictionary keyed by their
        // 1-based index.
        var byIndex = new Dictionary<int, JvmConstantEntry>(poolCount);
        var longSlots = new HashSet<int>();
        int index = 1;

        while (index < poolCount)
        {
            long entryStart = reader.Position;
            if (reader.Remaining < 1)
                return JvmClassResult.Failure(JvmClassFailureReason.Truncated, "pool_truncated",
                    index);

            byte tag = reader.ReadByte();
            JvmConstantEntry entry;
            switch ((JvmConstantTag)tag)
            {
                case JvmConstantTag.Utf8:
                    if (reader.Remaining < 2)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated, "utf8_length_missing", index);
                    ushort len = reader.ReadUInt16();
                    if ((int)len > MaxUtf8Length)
                        return JvmClassResult.Failure(JvmClassFailureReason.ConstantPoolEntryTooLarge,
                            $"utf8_length_{len}", index);
                    if (reader.Remaining < len)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "utf8_truncated", index);
                    var slice = data.Slice((int)reader.Position, len);
                    if (!ModifiedUtf8Decoder.TryDecode(slice, out string utf8, out string reason))
                        return JvmClassResult.Failure(JvmClassFailureReason.InvalidModifiedUtf8,
                            reason, index);
                    entry = new JvmConstantEntry(index, JvmConstantTag.Utf8, entryStart,
                        utf8, null, null, null, null, null, null, null, null, null);
                    reader.Skip(len);
                    break;

                case JvmConstantTag.Integer:
                    if (reader.Remaining < 4)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "int_truncated", index);
                    entry = new JvmConstantEntry(index, JvmConstantTag.Integer, entryStart,
                        null, null, null, null, reader.ReadInt32(), null, null, null, null, null);
                    break;

                case JvmConstantTag.Float:
                    if (reader.Remaining < 4)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "float_truncated", index);
                    entry = new JvmConstantEntry(index, JvmConstantTag.Float, entryStart,
                        null, null, null, null, null, null, null, null, null, null);
                    reader.Skip(4);
                    break;

                case JvmConstantTag.Long:
                    if (reader.Remaining < 8)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "long_truncated", index);
                    entry = new JvmConstantEntry(index, JvmConstantTag.Long, entryStart,
                        null, null, null, null, reader.ReadInt64(), null, null, null, null, null);
                    longSlots.Add(index);
                    longSlots.Add(index + 1);
                    break;

                case JvmConstantTag.Double:
                    if (reader.Remaining < 8)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "double_truncated", index);
                    long bits = reader.ReadInt64();
                    double d = BitConverter.Int64BitsToDouble(bits);
                    entry = new JvmConstantEntry(index, JvmConstantTag.Double, entryStart,
                        null, null, null, null, null, d, null, null, null, null);
                    longSlots.Add(index);
                    longSlots.Add(index + 1);
                    break;

                case JvmConstantTag.Class:
                    {
                        if (reader.Remaining < 2)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "class_truncated", index);
                        ushort nameIndex = reader.ReadUInt16();
                        entry = new JvmConstantEntry(index, JvmConstantTag.Class, entryStart,
                            null, null, null, null, null, null, nameIndex, null, null, null);
                        break;
                    }

                case JvmConstantTag.String:
                    {
                        if (reader.Remaining < 2)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "string_truncated", index);
                        ushort stringIndex = reader.ReadUInt16();
                        entry = new JvmConstantEntry(index, JvmConstantTag.String, entryStart,
                            null, null, null, null, null, null, null, null, null, stringIndex);
                        break;
                    }

                case JvmConstantTag.FieldRef:
                case JvmConstantTag.MethodRef:
                case JvmConstantTag.InterfaceMethodRef:
                    {
                        if (reader.Remaining < 4)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "ref_truncated", index);
                        ushort classIndex = reader.ReadUInt16();
                        ushort ntIndex = reader.ReadUInt16();
                        JvmConstantTag refTag = (JvmConstantTag)tag;
                        entry = new JvmConstantEntry(index, refTag, entryStart,
                            null, null, null, null, null, null, null, classIndex, null, null)
                        {
                            DescriptorIndex = ntIndex
                        };
                        break;
                    }

                case JvmConstantTag.NameAndType:
                    {
                        if (reader.Remaining < 4)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "nameandtype_truncated", index);
                        ushort nameIndex = reader.ReadUInt16();
                        ushort descIndex = reader.ReadUInt16();
                        entry = new JvmConstantEntry(index, JvmConstantTag.NameAndType, entryStart,
                            null, null, null, null, null, null, null, nameIndex, descIndex, null);
                        break;
                    }

                case JvmConstantTag.MethodHandle:
                    if (reader.Remaining < 3)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "methodhandle_truncated", index);
                    reader.Skip(3);
                    entry = new JvmConstantEntry(index, JvmConstantTag.MethodHandle, entryStart,
                        null, null, null, null, null, null, null, null, null, null);
                    break;

                case JvmConstantTag.MethodType:
                    if (reader.Remaining < 2)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "methodtype_truncated", index);
                    reader.Skip(2);
                    entry = new JvmConstantEntry(index, JvmConstantTag.MethodType, entryStart,
                        null, null, null, null, null, null, null, null, null, null);
                    break;

                case JvmConstantTag.Dynamic:
                case JvmConstantTag.InvokeDynamic:
                    if (reader.Remaining < 4)
                        return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                            "dynamic_truncated", index);
                    reader.Skip(4);
                    entry = new JvmConstantEntry(index, (JvmConstantTag)tag, entryStart,
                        null, null, null, null, null, null, null, null, null, null);
                    break;

                case JvmConstantTag.Module:
                    {
                        if (reader.Remaining < 2)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "module_truncated", index);
                        ushort nameIndex = reader.ReadUInt16();
                        entry = new JvmConstantEntry(index, JvmConstantTag.Module, entryStart,
                            null, null, null, null, null, null, null, nameIndex, null, null);
                        break;
                    }

                case JvmConstantTag.Package:
                    {
                        if (reader.Remaining < 2)
                            return JvmClassResult.Failure(JvmClassFailureReason.Truncated,
                                "package_truncated", index);
                        ushort nameIndex = reader.ReadUInt16();
                        entry = new JvmConstantEntry(index, JvmConstantTag.Package, entryStart,
                            null, null, null, null, null, null, null, nameIndex, null, null);
                        break;
                    }

                default:
                    return JvmClassResult.Failure(JvmClassFailureReason.UnknownPoolTag,
                        $"tag_{tag}", index);
            }

            byIndex[index] = entry;
            poolList.Add(entry);

            if (longSlots.Contains(index))
                index++;
            index++;
        }

        // Resolve Name/Descriptor/Class cross-references
        ResolveReferences(poolList, byIndex);

        // We have read poolCount-1 entries; the this_class / super_class /
        // interfaces / fields / methods headers come next. We don't need
        // them to extract strings, but we need the class name to make the
        // result useful. Try to read this_class if bytes remain.
        string? className = null;
        if (reader.Remaining >= 6)
        {
            ushort accessFlags = reader.ReadUInt16();
            ushort thisClass = reader.ReadUInt16();
            ushort superClass = reader.ReadUInt16();
            if (thisClass >= 1 && byIndex.TryGetValue(thisClass, out var thisEntry)
                && thisEntry.Tag == JvmConstantTag.Class
                && thisEntry.ClassNameIndex is ushort cni
                && byIndex.TryGetValue(cni, out var nameEntry)
                && nameEntry.Tag == JvmConstantTag.Utf8)
            {
                className = nameEntry.Value;
            }
            _ = accessFlags;
            _ = superClass;
        }

        return new JvmClassResult(
            IsValid: true,
            ClassName: className,
            MinorVersion: minor,
            MajorVersion: major,
            ConstantPool: poolList,
            FailureReason: JvmClassFailureReason.None,
            FailurePoolIndex: null,
            FailureDetail: null);
    }

    private static void ResolveReferences(
        List<JvmConstantEntry> pool,
        Dictionary<int, JvmConstantEntry> byIndex)
    {
        for (int i = 0; i < pool.Count; i++)
        {
            var entry = pool[i];
            switch (entry.Tag)
            {
                case JvmConstantTag.Class:
                    if (entry.ClassNameIndex is ushort cni
                        && byIndex.TryGetValue(cni, out var nameEntry)
                        && nameEntry.Tag == JvmConstantTag.Utf8)
                    {
                        pool[i] = entry with { ResolvedClassName = nameEntry.Value };
                    }
                    break;

                case JvmConstantTag.String:
                    if (entry.StringIndex is ushort si
                        && byIndex.TryGetValue(si, out var strEntry)
                        && strEntry.Tag == JvmConstantTag.Utf8)
                    {
                        pool[i] = entry with { Value = strEntry.Value };
                    }
                    break;

                case JvmConstantTag.NameAndType:
                    {
                        string? name = null;
                        string? desc = null;
                        if (entry.NameIndex is ushort ni
                            && byIndex.TryGetValue(ni, out var nm)
                            && nm.Tag == JvmConstantTag.Utf8)
                        {
                            name = nm.Value;
                        }
                        if (entry.DescriptorIndex is ushort di
                            && byIndex.TryGetValue(di, out var ds)
                            && ds.Tag == JvmConstantTag.Utf8)
                        {
                            desc = ds.Value;
                        }
                        if (name != null || desc != null)
                            pool[i] = entry with { Name = name, Descriptor = desc };
                        break;
                    }

                case JvmConstantTag.FieldRef:
                case JvmConstantTag.MethodRef:
                case JvmConstantTag.InterfaceMethodRef:
                    {
                        string? clsName = null;
                        string? nm = null;
                        string? ds = null;
                        if (entry.ClassNameIndex is ushort ci
                            && byIndex.TryGetValue(ci, out var cEntry)
                            && cEntry.Tag == JvmConstantTag.Class
                            && cEntry.ClassNameIndex is ushort cni2
                            && byIndex.TryGetValue(cni2, out var cn2)
                            && cn2.Tag == JvmConstantTag.Utf8)
                        {
                            clsName = cn2.Value;
                        }
                        if (entry.DescriptorIndex is ushort nti
                            && byIndex.TryGetValue(nti, out var nt)
                            && nt.Tag == JvmConstantTag.NameAndType)
                        {
                            nm = nt.Name;
                            ds = nt.Descriptor;
                        }
                        if (clsName != null || nm != null || ds != null)
                            pool[i] = entry with { ResolvedClassName = clsName, Name = nm, Descriptor = ds };
                        break;
                    }

                case JvmConstantTag.Module:
                    if (entry.NameIndex is ushort mi
                        && byIndex.TryGetValue(mi, out var me)
                        && me.Tag == JvmConstantTag.Utf8)
                    {
                        pool[i] = entry with { Value = me.Value };
                    }
                    break;

                case JvmConstantTag.Package:
                    if (entry.NameIndex is ushort pi
                        && byIndex.TryGetValue(pi, out var pe)
                        && pe.Tag == JvmConstantTag.Utf8)
                    {
                        pool[i] = entry with { Value = pe.Value };
                    }
                    break;
            }
        }
    }

    private ref struct BigEndianReader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _position;

        public BigEndianReader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _position = 0;
        }

        public int Remaining => _data.Length - _position;

        public long Position => _position;

        public void Skip(int count) => _position += count;

        public byte ReadByte()
        {
            if (_position >= _data.Length)
                throw new EndOfStreamException();
            byte b = _data[_position];
            _position++;
            return b;
        }

        public ushort ReadUInt16()
        {
            if (_position + 2 > _data.Length)
                throw new EndOfStreamException();
            ushort v = (ushort)((_data[_position] << 8) | _data[_position + 1]);
            _position += 2;
            return v;
        }

        public short ReadInt16()
        {
            if (_position + 2 > _data.Length)
                throw new EndOfStreamException();
            short v = (short)((_data[_position] << 8) | _data[_position + 1]);
            _position += 2;
            return v;
        }

        public int ReadInt32()
        {
            if (_position + 4 > _data.Length)
                throw new EndOfStreamException();
            int v = (_data[_position] << 24)
                  | (_data[_position + 1] << 16)
                  | (_data[_position + 2] << 8)
                  | _data[_position + 3];
            _position += 4;
            return v;
        }

        public long ReadInt64()
        {
            if (_position + 8 > _data.Length)
                throw new EndOfStreamException();
            long v = ((long)_data[_position] << 56)
                   | ((long)_data[_position + 1] << 48)
                   | ((long)_data[_position + 2] << 40)
                   | ((long)_data[_position + 3] << 32)
                   | ((long)_data[_position + 4] << 24)
                   | ((long)_data[_position + 5] << 16)
                   | ((long)_data[_position + 6] << 8)
                   | _data[_position + 7];
            _position += 8;
            return v;
        }
    }
}
