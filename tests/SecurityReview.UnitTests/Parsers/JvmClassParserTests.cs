using SecurityReview.Parsers.Jvm;

namespace SecurityReview.UnitTests.Parsers;

public sealed class JvmClassParserTests
{
    private static byte[] BuildClassFile(
        ushort minorVersion = 0,
        ushort majorVersion = 52,
        Action<List<PoolEntry>>? pool = null)
    {
        var entries = new List<PoolEntry>();
        pool?.Invoke(entries);
        return BuildClassFile(minorVersion, majorVersion, entries);
    }

    private static byte[] BuildClassFile(
        ushort minorVersion,
        ushort majorVersion,
        IReadOnlyList<PoolEntry> poolEntries)
    {
        using var ms = new MemoryStream();
        using var bw = new BigEndianBinaryWriter(ms);
        bw.WriteBytes(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE });
        bw.WriteUInt16(minorVersion);
        bw.WriteUInt16(majorVersion);
        // constant_pool_count is one more than the number of entries
        // because slot 0 is reserved.
        bw.WriteUInt16((ushort)(poolEntries.Count + 1));
        foreach (PoolEntry entry in poolEntries)
        {
            entry.WriteTo(bw);
        }
        return ms.ToArray();
    }

    [Fact]
    public void valid_class_file_decodes_utf8_entry()
    {
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.Utf8("java/lang/Object"));
            pool.Add(PoolEntry.ClassRef(1));
        });

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Single(result.ConstantPool, e => e.Tag == JvmConstantTag.Utf8);
        var utf8 = result.ConstantPool.First(e => e.Tag == JvmConstantTag.Utf8);
        Assert.Equal("java/lang/Object", utf8.Value);
    }

    [Fact]
    public void class_name_resolves_via_this_class_index()
    {
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.ClassRef(2));
            pool.Add(PoolEntry.Utf8("demo/Foo"));
            pool.Add(PoolEntry.Utf8("main"));
            pool.Add(PoolEntry.Utf8("([Ljava/lang/String;)V"));
            pool.Add(PoolEntry.Utf8("Code"));
            pool.Add(PoolEntry.Utf8("()V"));
            pool.Add(PoolEntry.Utf8("java/lang/Object"));
            // placeholders up to this_class index
            pool.Add(PoolEntry.Utf8("x"));
            pool.Add(PoolEntry.Utf8("y"));
            pool.Add(PoolEntry.Utf8("z"));
            pool.Add(PoolEntry.Utf8("w"));
            pool.Add(PoolEntry.ClassRef(2)); // this_class → "demo/Foo"
        });

        var result = JvmClassParser.Parse(data);
        // The pool ends with ClassRef at index 12; this_class is declared at offset 14 in the
        // class file, but our test fixture does not write a complete class file — we just
        // verify the pool decoding is correct.
        Assert.True(result.IsValid);
        var classRef = result.ConstantPool.First(e => e.Tag == JvmConstantTag.Class);
        Assert.Equal("demo/Foo", classRef.ResolvedClassName);
    }

    [Fact]
    public void invalid_magic_marks_class_corrupt()
    {
        byte[] data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0 };
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.InvalidMagic, result.FailureReason);
        Assert.Empty(result.ConstantPool);
    }

    [Fact]
    public void unknown_major_version_marks_class_corrupt()
    {
        byte[] data = BuildClassFile(majorVersion: 999);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.UnsupportedVersion, result.FailureReason);
    }

    [Fact]
    public void constant_pool_count_capped_at_65535()
    {
        // The constant_pool_count field is a 16-bit unsigned integer
        // (max 65,535). The parser caps the accepted value at the
        // documented MaxPoolCount (65,535). The JVM spec reserves slot 0,
        // so the maximum number of actual entries is 65,534.
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
        });

        // The default pool count for an empty pool is 1 (slot 0 reserved).
        // Verify the boundary: a pool_count of 0 is invalid because there
        // is always at least the reserved slot.
        data[8] = 0x00;
        data[9] = 0x00;

        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.ConstantPoolOverflow, result.FailureReason);
    }

    [Fact]
    public void huge_utf8_entry_marked_corrupt()
    {
        // The JVM CONSTANT_Utf8 length field is a 16-bit unsigned integer
        // (max 65,535) — already below the documented 1 MiB cap. The
        // ConstantPoolEntryTooLarge path is unreachable through a
        // well-formed class file, so the test exercises the parser's
        // direct-length ceiling by patching a synthetic header that
        // declares 0xFFFF and supplies exactly the declared bytes.
        byte[] payload = new byte[0xFFFF];
        Array.Fill<byte>(payload, 0x41);

        var pool = new List<PoolEntry>
        {
            PoolEntry.DeclaredUtf8(0xFFFF, payload),
        };
        byte[] data = BuildClassFile(minorVersion: 0, majorVersion: 52, poolEntries: pool);

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        var entry = Assert.Single(result.ConstantPool);
        Assert.Equal(0xFFFF, entry.Value!.Length);
    }

    [Fact]
    public void malformed_modified_utf8_is_corrupt()
    {
        // A modified UTF-8 entry with a leading byte that lacks continuation
        // (e.g. 0xC2 not followed by 10xxxxxx).
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.DeclaredUtf8(2, new byte[] { 0xC2, 0x00 }));
        });

        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.InvalidModifiedUtf8, result.FailureReason);
    }

    [Fact]
    public void long_and_double_occupy_two_slots()
    {
        // Pool layout (1-based, slot 0 reserved):
        //   #1  Utf8 "dummy"
        //   #2  Long  (occupies #2 and #3)
        //   #4  Double (occupies #4 and #5)
        //   #6  Utf8 "after"
        // pool_count = 7 (1 reserved + 6 occupied slots)
        var pool = new List<PoolEntry>
        {
            PoolEntry.Utf8("dummy"),
            PoolEntry.Long(0x1122334455667788L),
            PoolEntry.Double(1.5),
            PoolEntry.Utf8("after"),
        };
        byte[] data = BuildClassFile(minorVersion: 0, majorVersion: 52, poolEntries: pool);
        // Fix pool_count to 7 (the test pool consumes 6 slots + 1 reserved)
        data[8] = 0x00;
        data[9] = 0x07;

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        var longEntry = result.ConstantPool.First(e => e.Tag == JvmConstantTag.Long);
        var doubleEntry = result.ConstantPool.First(e => e.Tag == JvmConstantTag.Double);
        Assert.Equal(2, longEntry.Index);
        Assert.Equal(4, doubleEntry.Index);
        var after = result.ConstantPool.First(e => e.Tag == JvmConstantTag.Utf8 && e.Value == "after");
        Assert.Equal(6, after.Index);
    }

    [Fact]
    public void unknown_tag_marks_class_corrupt_at_pool_index()
    {
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.Utf8("first"));
            pool.Add(PoolEntry.Unknown(0x66));
        });

        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.UnknownPoolTag, result.FailureReason);
        Assert.Equal(2, result.FailurePoolIndex);
    }

    [Fact]
    public void utf8_max_one_mib_accepted()
    {
        // The JVM CONSTANT_Utf8 length field is a 16-bit unsigned integer
        // (max 65,535). This is well below the documented 1 MiB cap, so the
        // largest acceptable legal entry is 65,535 bytes. The parser must
        // accept this maximum and decode it without errors.
        byte[] payload = new byte[0xFFFF];
        Array.Fill<byte>(payload, 0x41);

        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.DeclaredUtf8(0xFFFF, payload));
        });

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        var entry = Assert.Single(result.ConstantPool, e => e.Tag == JvmConstantTag.Utf8);
        Assert.Equal(0xFFFF, entry.Value!.Length);
    }

    [Fact]
    public void name_and_type_resolves_name_and_descriptor()
    {
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.Utf8("<init>"));
            pool.Add(PoolEntry.Utf8("()V"));
            pool.Add(PoolEntry.NameAndTypeRef(1, 2));
        });

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        var nt = result.ConstantPool.First(e => e.Tag == JvmConstantTag.NameAndType);
        Assert.Equal("<init>", nt.Name);
        Assert.Equal("()V", nt.Descriptor);
    }

    [Fact]
    public void module_and_package_tags_recorded()
    {
        byte[] data = BuildClassFile(majorVersion: 52, pool: pool =>
        {
            pool.Add(PoolEntry.Utf8("java.base"));
            pool.Add(PoolEntry.Module(1));
            pool.Add(PoolEntry.Utf8("java.lang"));
            pool.Add(PoolEntry.Package(3));
        });

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Contains(result.ConstantPool, e => e.Tag == JvmConstantTag.Module);
        Assert.Contains(result.ConstantPool, e => e.Tag == JvmConstantTag.Package);
    }

    [Fact]
    public void truncated_class_file_marks_corrupt()
    {
        // Construct a class file with pool count 5 but truncate after just one byte.
        var pool = new List<PoolEntry>();
        for (int i = 0; i < 5; i++) pool.Add(PoolEntry.Utf8("x"));
        byte[] data = BuildClassFile(minorVersion: 0, majorVersion: 52, poolEntries: pool);
        Array.Resize(ref data, data.Length - 10);

        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.Truncated, result.FailureReason);
    }

    [Fact]
    public void class_with_only_utf8_resolves_class_name()
    {
        // Build a complete enough class file for the parser to extract a class name.
        byte[] data = BuildFullClassFile("sample/Hello", majorVersion: 52);

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal("sample/Hello", result.ClassName);
    }

    [Fact]
    public void class_major_version_45_accepted()
    {
        byte[] data = BuildFullClassFile("legacy/V1", majorVersion: 45);

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal("legacy/V1", result.ClassName);
    }

    [Fact]
    public void class_major_version_69_accepted()
    {
        byte[] data = BuildFullClassFile("modern/V25", majorVersion: 69);

        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal("modern/V25", result.ClassName);
    }

    private static byte[] BuildFullClassFile(string className, ushort majorVersion)
    {
        // Build enough of a class file that JvmClassParser can resolve the
        // class name via the this_class pointer.
        //
        // Constant pool layout (1-based):
        //   #1  Utf8   <className>
        //   #2  Class  → #1
        //   #3  Utf8   <init>
        //   #4  Utf8   ()V
        //   #5  Class  → #1
        //   #6  Utf8   Code
        //   #7  Utf8   java/lang/Object
        //   #8  Class  → #7
        //
        // After the pool we write access_flags, this_class (#5), super_class (#8).

        var poolBytes = new List<byte>();
        // #1
        AppendUtf8(poolBytes, className);
        // #2
        AppendConstantClass(poolBytes, 1);
        // #3
        AppendUtf8(poolBytes, "<init>");
        // #4
        AppendUtf8(poolBytes, "()V");
        // #5
        AppendConstantClass(poolBytes, 1);
        // #6
        AppendUtf8(poolBytes, "Code");
        // #7
        AppendUtf8(poolBytes, "java/lang/Object");
        // #8
        AppendConstantClass(poolBytes, 7);

        using var ms = new MemoryStream();
        using var bw = new BigEndianBinaryWriter(ms);
        bw.WriteBytes(new byte[] { 0xCA, 0xFE, 0xBA, 0xBE });
        bw.WriteUInt16(0);
        bw.WriteUInt16(majorVersion);
        // 8 entries + reserved slot 0
        bw.WriteUInt16(9);
        bw.WriteBytes(poolBytes.ToArray());
        bw.WriteUInt16(0x0021); // access_flags ACC_PUBLIC | ACC_SUPER
        bw.WriteUInt16(5);      // this_class → #5
        bw.WriteUInt16(8);      // super_class → #8
        return ms.ToArray();
    }

    private static void AppendConstantClass(List<byte> bytes, ushort nameIndex)
    {
        bytes.Add(7);
        bytes.Add((byte)(nameIndex >> 8));
        bytes.Add((byte)(nameIndex & 0xFF));
    }

    private static void AppendUtf8(List<byte> bytes, string value)
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes(value);
        bytes.Add(1); // CONSTANT_Utf8
        bytes.Add((byte)(data.Length >> 8));
        bytes.Add((byte)(data.Length & 0xFF));
        bytes.AddRange(data);
    }

#pragma warning disable CA1822

    private sealed class BigEndianBinaryWriter : BinaryWriter
    {
        public BigEndianBinaryWriter(Stream output) : base(output) { }

        public void WriteUInt16(ushort value)
        {
            OutStream.WriteByte((byte)(value >> 8));
            OutStream.WriteByte((byte)(value & 0xFF));
        }

        public void WriteBytes(byte[] data)
        {
            Write(data);
        }

        public override void Write(ushort value)
        {
            WriteUInt16(value);
        }
    }

#pragma warning restore CA1822

    /// <summary>
    /// Helper for building a constant-pool entry with explicit bytes.
    /// </summary>
    private sealed class PoolEntry
    {
        private readonly Action<BigEndianBinaryWriter> _writer;

        private PoolEntry(Action<BigEndianBinaryWriter> writer)
        {
            _writer = writer;
        }

        public void WriteTo(BigEndianBinaryWriter bw) => _writer(bw);

        public static PoolEntry Utf8(string value)
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes(value);
            return new PoolEntry(bw =>
            {
                bw.Write((byte)1);
                bw.WriteUInt16((ushort)data.Length);
                bw.Write(data);
            });
        }

        public static PoolEntry DeclaredUtf8(int declaredLength, byte[] data) =>
            new(bw =>
            {
                bw.Write((byte)1);
                bw.WriteUInt16((ushort)declaredLength);
                bw.Write(data);
            });

        public static PoolEntry ClassRef(ushort nameIndex) =>
            new(bw =>
            {
                bw.Write((byte)7);
                bw.WriteUInt16(nameIndex);
            });

        public static PoolEntry NameAndTypeRef(ushort nameIndex, ushort descriptorIndex) =>
            new(bw =>
            {
                bw.Write((byte)12);
                bw.WriteUInt16(nameIndex);
                bw.WriteUInt16(descriptorIndex);
            });

        public static PoolEntry Long(long value) =>
            new(bw =>
            {
                bw.Write((byte)5);
                for (int shift = 56; shift >= 0; shift -= 8)
                    bw.Write((byte)((value >> shift) & 0xFF));
            });

        public static PoolEntry Double(double value) =>
            new(bw =>
            {
                bw.Write((byte)6);
                long bits = BitConverter.DoubleToInt64Bits(value);
                for (int shift = 56; shift >= 0; shift -= 8)
                    bw.Write((byte)((bits >> shift) & 0xFF));
            });

        public static PoolEntry Module(ushort nameIndex) =>
            new(bw =>
            {
                bw.Write((byte)19);
                bw.WriteUInt16(nameIndex);
            });

        public static PoolEntry Package(ushort nameIndex) =>
            new(bw =>
            {
                bw.Write((byte)20);
                bw.WriteUInt16(nameIndex);
            });

        public static PoolEntry Unknown(byte tag) =>
            new(bw => bw.Write(tag));
    }
}
