namespace SecurityReview.Parsers.Binary;

/// <summary>
/// Failure reason for an ELF file that the parser could not consume.
/// </summary>
public enum ElfMetadataFailureReason
{
    None,
    InvalidMagic,
    InvalidClass,
    InvalidData,
    Truncated,
    InvalidHeader,
    TooManySections,
    InvalidStringTable,
}

/// <summary>
/// ELF section type. Mirrors the values in <c>elf.h</c>.
/// </summary>
public enum ElfSectionType : uint
{
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    ShLib = 10,
    DynamicSymbolTable = 11,
}

/// <summary>
/// A single ELF section header entry.
/// </summary>
public sealed record ElfSectionHeader(
    string Name,
    ElfSectionType Type,
    ulong Flags,
    ulong Address,
    ulong Offset,
    ulong Size,
    uint Link,
    uint Info,
    ulong AddrAlign,
    ulong EntSize,
    long NameOffset);

/// <summary>
/// Result of <see cref="ElfMetadataParser.Parse"/>. Carries the section table,
/// notes, build-id, and dynamic-needed library names when available.
/// </summary>
public sealed record ElfMetadataResult(
    bool IsValid,
    bool Is64Bit,
    bool IsLittleEndian,
    ushort Machine,
    IReadOnlyList<ElfSectionHeader> Sections,
    IReadOnlyList<string> NoteNames,
    IReadOnlyList<string> BuildIdNotes,
    IReadOnlyList<string> DynamicNeeded,
    ElfMetadataFailureReason FailureReason,
    string? FailureDetail)
{
    public static ElfMetadataResult Failure(ElfMetadataFailureReason reason, string detail) =>
        new(false, false, false, 0,
            Array.Empty<ElfSectionHeader>(),
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
            reason, detail);

    public static ElfMetadataResult Empty { get; } =
        new(true, false, false, 0,
            Array.Empty<ElfSectionHeader>(),
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(),
            ElfMetadataFailureReason.None, null);
}

/// <summary>
/// Statically inspects an ELF binary. Validates the magic, class, endianness,
/// header bounds, and section count (≤65,535). Reads the section table,
/// section names, the note table (build-id, etc.), and the dynamic-needed
/// library names. Never disassembles the file.
/// </summary>
public static class ElfMetadataParser
{
    /// <summary>Hard cap on the number of ELF sections (e_shnum is uint16).</summary>
    public const int MaxSections = 65_535;

    /// <summary>ELF magic number.</summary>
    public static ReadOnlySpan<byte> Magic => new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' };

    /// <summary>Parse an ELF file. The parser never throws on malformed input.</summary>
    public static ElfMetadataResult Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidMagic, "header_short");

        if (data[0] != 0x7F || data[1] != (byte)'E' || data[2] != (byte)'L' || data[3] != (byte)'F')
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidMagic, "magic_mismatch");

        bool is64 = data[4] == 2;
        bool is32 = data[4] == 1;
        if (!is32 && !is64)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidClass, $"class_{data[4]}");

        bool littleEndian = data[5] == 1;
        bool bigEndian = data[5] == 2;
        if (!littleEndian && !bigEndian)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidData, $"data_{data[5]}");

        int headerSize = is64 ? 64 : 52;
        if (data.Length < headerSize)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidHeader, "header_truncated");

        ushort machine = ReadU16(data, is64, littleEndian, is64 ? 18 : 18);

        ulong eShoff = is64
            ? ReadU64(data, littleEndian, 40)
            : ReadU32(data, littleEndian, 32);
        ushort eShentsize = ReadU16(data, is64, littleEndian, is64 ? 58 : 46);
        ushort eShnum = ReadU16(data, is64, littleEndian, is64 ? 60 : 48);
        ushort eShstrndx = ReadU16(data, is64, littleEndian, is64 ? 62 : 50);

        if (eShnum > MaxSections)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.TooManySections, $"shnum_{eShnum}");

        // Validate section table bounds with checked arithmetic
        long sectionTableBytes;
        try
        {
            sectionTableBytes = checked((long)eShnum * eShentsize);
        }
        catch (OverflowException)
        {
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.TooManySections, "overflow");
        }
        long sectionTableEnd;
        try
        {
            sectionTableEnd = checked((long)eShoff + sectionTableBytes);
        }
        catch (OverflowException)
        {
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.TooManySections, "overflow_end");
        }
        if ((long)eShoff < headerSize || sectionTableEnd > data.Length)
            return ElfMetadataResult.Failure(ElfMetadataFailureReason.InvalidHeader, "shoff_out_of_range");

        // Read the section name string table first so we can resolve names
        ElfSectionHeader? shstrtab = null;
        if (eShstrndx > 0 && eShstrndx < eShnum)
        {
            shstrtab = ReadSectionHeader(data, is64, littleEndian, eShoff, eShentsize, eShstrndx, null);
        }

        var sections = new List<ElfSectionHeader>(eShnum);
        for (int i = 0; i < eShnum; i++)
        {
            var sh = ReadSectionHeader(data, is64, littleEndian, eShoff, eShentsize, (ushort)i, shstrtab);
            sections.Add(sh);
        }

        var noteNames = new List<string>();
        var buildIds = new List<string>();
        var dynamicNeeded = new List<string>();

        foreach (var sh in sections)
        {
            if (sh.Type == ElfSectionType.Note)
            {
                CollectNotes(data, sh.Offset, sh.Size, noteNames, buildIds);
            }
            else if (sh.Type == ElfSectionType.Dynamic && sh.Size > 0)
            {
                CollectDynamicNeeded(data, sh.Offset, sh.Size, is64, littleEndian, sections,
                    dynamicNeeded);
            }
        }

        return new ElfMetadataResult(true, is64, littleEndian, machine,
            sections, noteNames, buildIds, dynamicNeeded,
            ElfMetadataFailureReason.None, null);
    }

    private static ElfSectionHeader ReadSectionHeader(
        ReadOnlySpan<byte> data,
        bool is64,
        bool littleEndian,
        ulong eShoff,
        ushort eShentsize,
        ushort index,
        ElfSectionHeader? shstrtab)
    {
        long shPos = (long)eShoff + (long)index * eShentsize;
        int shentsize = is64 ? 64 : 40;

        if (shPos + shentsize > data.Length)
        {
            return new ElfSectionHeader(
                Name: string.Empty,
                Type: ElfSectionType.Null,
                Flags: 0, Address: 0, Offset: 0, Size: 0,
                Link: 0, Info: 0, AddrAlign: 0, EntSize: 0, NameOffset: 0);
        }

        uint shName = ReadU32(data, littleEndian, (int)shPos);
        uint shType = ReadU32(data, littleEndian, (int)shPos + 4);
        ulong shFlags = is64
            ? ReadU64(data, littleEndian, (int)shPos + 8)
            : ReadU32(data, littleEndian, (int)shPos + 8);
        ulong shAddr = is64
            ? ReadU64(data, littleEndian, (int)shPos + 16)
            : ReadU32(data, littleEndian, (int)shPos + 12);
        ulong shOffset = is64
            ? ReadU64(data, littleEndian, (int)shPos + 24)
            : ReadU32(data, littleEndian, (int)shPos + 16);
        ulong shSize = is64
            ? ReadU64(data, littleEndian, (int)shPos + 32)
            : ReadU32(data, littleEndian, (int)shPos + 20);
        uint shLink = ReadU32(data, littleEndian, (int)shPos + (is64 ? 40 : 24));
        uint shInfo = ReadU32(data, littleEndian, (int)shPos + (is64 ? 44 : 28));
        ulong shAddrAlign = is64
            ? ReadU64(data, littleEndian, (int)shPos + 48)
            : ReadU32(data, littleEndian, (int)shPos + 32);
        ulong shEntSize = is64
            ? ReadU64(data, littleEndian, (int)shPos + 56)
            : ReadU32(data, littleEndian, (int)shPos + 36);

        string name = ResolveName(data, shstrtab, shName);
        return new ElfSectionHeader(
            Name: name,
            Type: (ElfSectionType)shType,
            Flags: shFlags,
            Address: shAddr,
            Offset: shOffset,
            Size: shSize,
            Link: shLink,
            Info: shInfo,
            AddrAlign: shAddrAlign,
            EntSize: shEntSize,
            NameOffset: shName);
    }

    private static string ResolveName(ReadOnlySpan<byte> data, ElfSectionHeader? shstrtab, uint nameOffset)
    {
        if (shstrtab is null || shstrtab.Size == 0)
            return string.Empty;
        if ((long)shstrtab.Offset + nameOffset >= data.Length)
            return string.Empty;
        long end = Math.Min((long)shstrtab.Offset + (long)shstrtab.Size, data.Length);
        long start = (long)shstrtab.Offset + (long)nameOffset;
        int length = 0;
        while (start + length < end && data[(int)(start + length)] != 0)
            length++;
        return System.Text.Encoding.ASCII.GetString(data.Slice((int)start, length));
    }

    private static void CollectNotes(
        ReadOnlySpan<byte> data, ulong offset, ulong size,
        List<string> noteNames, List<string> buildIds)
    {
        long end = (long)offset + (long)size;
        if (end > data.Length) end = data.Length;
        long pos = (long)offset;
        // Each note: namesz (4), descsz (4), type (4), name (aligned to 4), desc (aligned to 4)
        while (pos + 12 <= end)
        {
            uint namesz = ReadU32(data, true, (int)pos);
            uint descsz = ReadU32(data, true, (int)pos + 4);
            uint type = ReadU32(data, true, (int)pos + 8);
            if (namesz == 0 && descsz == 0 && type == 0) break;
            long nameStart = pos + 12;
            if (nameStart + namesz > end) break;
            string name = System.Text.Encoding.ASCII.GetString(
                data.Slice((int)nameStart, (int)Math.Min(namesz, 256)));
            if (!string.IsNullOrEmpty(name))
                noteNames.Add(name);

            if (name.StartsWith("GNU", StringComparison.Ordinal) && type == 3 /* NT_GNU_BUILD_ID */ && descsz > 0)
            {
                long descStart = nameStart + Align4((long)namesz);
                if (descStart + descsz <= end)
                {
                    var bytes = data.Slice((int)descStart, (int)descsz);
                    buildIds.Add(ToHex(bytes));
                }
            }

            long descAligned = nameStart + Align4((long)namesz);
            long nextNote = descAligned + Align4((long)descsz);
            if (nextNote <= pos)
                break;
            pos = nextNote;
        }
    }

    private static void CollectDynamicNeeded(
        ReadOnlySpan<byte> data, ulong offset, ulong size,
        bool is64, bool littleEndian,
        List<ElfSectionHeader> sections,
        List<string> dynamicNeeded)
    {
        long end = (long)offset + (long)size;
        if (end > data.Length) end = data.Length;
        int entrySize = is64 ? 16 : 8;
        long pos = (long)offset;
        while (pos + entrySize <= end)
        {
            ulong tag = is64
                ? ReadU64(data, littleEndian, (int)pos)
                : ReadU32(data, littleEndian, (int)pos);
            ulong val = is64
                ? ReadU64(data, littleEndian, (int)pos + 8)
                : ReadU32(data, littleEndian, (int)pos + 4);

            if (tag == 0 /* DT_NULL */) break;

            if (tag == 1 /* DT_NEEDED */)
            {
                var strtab = FindStringTable(sections, val);
                if (strtab is not null && (long)strtab.Offset + (long)val < data.Length)
                {
                    long nameStart = (long)strtab.Offset + (long)val;
                    long nameEnd = Math.Min((long)strtab.Offset + (long)strtab.Size, data.Length);
                    int len = 0;
                    while (nameStart + len < nameEnd && data[(int)(nameStart + len)] != 0)
                        len++;
                    string name = System.Text.Encoding.ASCII.GetString(data.Slice((int)nameStart, len));
                    if (!string.IsNullOrEmpty(name))
                        dynamicNeeded.Add(name);
                }
            }

            pos += entrySize;
        }
    }

    private static ElfSectionHeader? FindStringTable(List<ElfSectionHeader> sections, ulong offset)
    {
        // The string table index for the dynamic section is stored in the
        // sh_link of the .dynamic section. The caller would normally pass
        // it in, but for simplicity here we just look up any SHT_STRTAB
        // whose offset matches the value (best effort).
        foreach (var sh in sections)
        {
            if (sh.Type == ElfSectionType.StrTab && sh.Offset == offset)
                return sh;
        }
        // Fallback: pick the first STRTAB
        foreach (var sh in sections)
        {
            if (sh.Type == ElfSectionType.StrTab)
                return sh;
        }
        return null;
    }

    private static long Align4(long value) => (value + 3) & ~3L;

    private static string ToHex(ReadOnlySpan<byte> data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 2);
        for (int i = 0; i < data.Length; i++)
            sb.Append(data[i].ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static ushort ReadU16(ReadOnlySpan<byte> data, bool is64, bool littleEndian, int offset)
    {
        if (offset + 2 > data.Length) return 0;
        if (littleEndian)
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        return (ushort)((data[offset] << 8) | data[offset + 1]);
    }

    private static uint ReadU32(ReadOnlySpan<byte> data, bool littleEndian, int offset)
    {
        if (offset + 4 > data.Length) return 0;
        if (littleEndian)
            return (uint)(data[offset]
                       | (data[offset + 1] << 8)
                       | (data[offset + 2] << 16)
                       | (data[offset + 3] << 24));
        return (uint)((data[offset] << 24)
                   | (data[offset + 1] << 16)
                   | (data[offset + 2] << 8)
                   | data[offset + 3]);
    }

    private static ulong ReadU64(ReadOnlySpan<byte> data, bool littleEndian, int offset)
    {
        if (offset + 8 > data.Length) return 0;
        if (littleEndian)
        {
            return (ulong)data[offset]
                 | ((ulong)data[offset + 1] << 8)
                 | ((ulong)data[offset + 2] << 16)
                 | ((ulong)data[offset + 3] << 24)
                 | ((ulong)data[offset + 4] << 32)
                 | ((ulong)data[offset + 5] << 40)
                 | ((ulong)data[offset + 6] << 48)
                 | ((ulong)data[offset + 7] << 56);
        }
        return ((ulong)data[offset] << 56)
             | ((ulong)data[offset + 1] << 48)
             | ((ulong)data[offset + 2] << 40)
             | ((ulong)data[offset + 3] << 32)
             | ((ulong)data[offset + 4] << 24)
             | ((ulong)data[offset + 5] << 16)
             | ((ulong)data[offset + 6] << 8)
             | (ulong)data[offset + 7];
    }
}
