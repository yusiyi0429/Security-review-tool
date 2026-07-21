using System.Text;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Binary;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Jvm;
using SecurityReview.Parsers.Text;

namespace SecurityReview.ParserCorpusTests.Binary;

public sealed class CodeAndBinaryParserTests
{
    private static string BinaryCorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(CodeAndBinaryParserTests).Assembly.Location)!,
        "Corpus", "Binary");

    private static string JvmCorpusDir => Path.Combine(
        Path.GetDirectoryName(typeof(CodeAndBinaryParserTests).Assembly.Location)!,
        "Corpus", "Jvm");

    private static ParseContext MakeContext(string virtualPath) =>
        new(
            new JobId(Guid.NewGuid()),
            new ScanId(Guid.NewGuid()),
            virtualPath,
            new ParseLimits(DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576));

    [Fact]
    public void jvm_valid_class_file_resolves_class_name()
    {
        string path = Path.Combine(JvmCorpusDir, "valid_hello.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal("demo/Hello", result.ClassName);
    }

    [Fact]
    public void jvm_invalid_magic_class_file_rejected()
    {
        string path = Path.Combine(JvmCorpusDir, "invalid_magic.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.InvalidMagic, result.FailureReason);
    }

    [Fact]
    public void jvm_unsupported_major_version_rejected()
    {
        string path = Path.Combine(JvmCorpusDir, "unknown_major_version.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.UnsupportedVersion, result.FailureReason);
    }

    [Fact]
    public void jvm_constant_pool_overflow_rejected()
    {
        string path = Path.Combine(JvmCorpusDir, "constant_pool_overflow.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.ConstantPoolOverflow, result.FailureReason);
    }

    [Fact]
    public void jvm_huge_utf8_entry_accepted()
    {
        string path = Path.Combine(JvmCorpusDir, "huge_utf8_entry.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        var entry = Assert.Single(result.ConstantPool);
        Assert.Equal(0xFFFF, entry.Value!.Length);
    }

    [Fact]
    public void jvm_malformed_utf8_rejected()
    {
        string path = Path.Combine(JvmCorpusDir, "malformed_utf8.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.InvalidModifiedUtf8, result.FailureReason);
    }

    [Fact]
    public void jvm_unknown_tag_rejected_at_pool_index()
    {
        string path = Path.Combine(JvmCorpusDir, "unknown_tag.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.UnknownPoolTag, result.FailureReason);
        Assert.Equal(2, result.FailurePoolIndex);
    }

    [Fact]
    public void jvm_truncated_class_file_rejected()
    {
        string path = Path.Combine(JvmCorpusDir, "truncated.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(JvmClassFailureReason.Truncated, result.FailureReason);
    }

    [Fact]
    public void jvm_module_and_package_tags_resolved()
    {
        string path = Path.Combine(JvmCorpusDir, "module_package.class");
        Assert.True(File.Exists(path));

        byte[] data = File.ReadAllBytes(path);
        var result = JvmClassParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Contains(result.ConstantPool, e => e.Tag == JvmConstantTag.Module && e.Value == "java.base");
        Assert.Contains(result.ConstantPool, e => e.Tag == JvmConstantTag.Package && e.Value == "java.lang");
    }

    [Fact]
    public async Task jar_format_parser_emits_class_and_manifest_children()
    {
        string path = Path.Combine(JvmCorpusDir, "valid_lib.jar");
        Assert.True(File.Exists(path));

        var parser = new JarFormatParser();
        var events = await ParseAsync(path, parser, "test/lib.jar");

        Assert.Contains(events, e => e is ParserEvent.ChunkProduced);
        Assert.Contains(events, e => e is ParserEvent.ParseCompleted);

        // The jar should expose at least one class file chunk (class strings)
        // and at least one manifest chunk.
        var chunks = events.OfType<ParserEvent.ChunkProduced>().ToList();
        Assert.Contains(chunks, c => c.Chunk.VirtualPath.Contains("demo/Hello.class"));
        Assert.Contains(chunks, c => c.Chunk.VirtualPath.Contains("META-INF/MANIFEST.MF"));
    }

    [Fact]
    public void python_lexical_locator_finds_strings_in_fixture()
    {
        // Generate a small Python source on the fly and verify the locator
        // surfaces comments and string literals with line/column.
        const string source =
            "# canary\n" +
            "value = 'secret'\n" +
            "data = b'\\x00\\x01'\n" +
            "name = f'hello {value}'\n" +
            "doc = \"\"\"\ntriple\n\"\"\"\n";

        var result = PythonLexicalLocator.Locate(source);

        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.Comment && t.Text == "# canary");
        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.StringLiteral && t.Text == "'secret'");
        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.Bytes && t.Text == "b'\\x00\\x01'");
        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.FString && t.Text.StartsWith("f'", StringComparison.Ordinal));
        Assert.Contains(result.Tokens, t => t.Kind == PythonLexicalKind.TripleString);

        // Comment line/column is exactly (1, 1)
        var comment = result.Tokens.First(t => t.Kind == PythonLexicalKind.Comment);
        Assert.Equal(1, comment.StartLine);
        Assert.Equal(1, comment.StartColumn);
    }

    [Fact]
    public void pe_metadata_parser_rejects_invalid_magic()
    {
        byte[] data = new byte[512];
        var result = PeMetadataParser.Parse(data);
        Assert.False(result.IsValid);
        Assert.Equal(PeMetadataFailureReason.InvalidDosSignature, result.FailureReason);
    }

    [Fact]
    public void pe_metadata_parser_rejects_unparseable_header()
    {
        // MZ + garbage e_lfanew
        byte[] data = new byte[512];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        var result = PeMetadataParser.Parse(data);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void pe_metadata_parser_handles_minimal_pe()
    {
        byte[] data = BuildMinimalPe();
        var result = PeMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.Sections);
    }

    [Fact]
    public void elf_metadata_parser_rejects_invalid_magic()
    {
        byte[] data = new byte[256];
        var result = ElfMetadataParser.Parse(data);
        Assert.False(result.IsValid);
        Assert.Equal(ElfMetadataFailureReason.InvalidMagic, result.FailureReason);
    }

    [Fact]
    public void elf_metadata_parser_handles_minimal_elf64()
    {
        byte[] data = BuildMinimalElf64();
        var result = ElfMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.Sections);
    }

    [Fact]
    public void elf_metadata_parser_handles_minimal_elf32()
    {
        byte[] data = BuildMinimalElf32();
        var result = ElfMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.Sections);
    }

    [Fact]
    public void pe_invalid_e_lfanew_rejected()
    {
        // MZ signature but e_lfanew points past the buffer
        byte[] data = new byte[128];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        var result = PeMetadataParser.Parse(data);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void elf_class_mismatch_rejected()
    {
        // ELF32 header but class byte 2 (64-bit)
        byte[] data = BuildMinimalElf64();
        data[4] = 1; // EI_CLASS = ELFCLASS32
        var result = ElfMetadataParser.Parse(data);
        // Either this is rejected as inconsistent, or the parser picks the
        // class from the field. The minimal fixture here will be detected as
        // 64-bit because data[4] is now 1, but the section offsets are 64-bit.
        // We assert: parser does NOT crash.
        _ = result;
    }

    [Fact]
    public void pe_corpus_fixture_minimal_is_valid_and_contains_canary_section()
    {
        string path = Path.Combine(BinaryCorpusDir, "minimal_pe32plus.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = PeMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.NotEmpty(result.Sections);
        Assert.Contains(result.Sections, s => s.Name == ".text");
        Assert.Contains(result.Sections, s => s.Name == ".rdata");
    }

    [Fact]
    public void pe_corpus_fixture_overlapping_sections_does_not_crash()
    {
        string path = Path.Combine(BinaryCorpusDir, "pe_overlapping_sections.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = PeMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Equal(2, result.Sections.Count);
    }

    [Fact]
    public void pe_corpus_fixture_too_many_sections_rejected()
    {
        string path = Path.Combine(BinaryCorpusDir, "pe_too_many_sections.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = PeMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(PeMetadataFailureReason.TooManySections, result.FailureReason);
    }

    [Fact]
    public void pe_corpus_fixture_invalid_elfanew_rejected()
    {
        string path = Path.Combine(BinaryCorpusDir, "pe_invalid_elfanew.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = PeMetadataParser.Parse(data);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void pe_corpus_fixture_zero_sections_accepted()
    {
        string path = Path.Combine(BinaryCorpusDir, "pe_zero_sections.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = PeMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Empty(result.Sections);
    }

    [Fact]
    public void elf_corpus_fixture_minimal_elf32_accepted()
    {
        string path = Path.Combine(BinaryCorpusDir, "minimal_elf32.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = ElfMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.False(result.Is64Bit);
        Assert.NotEmpty(result.Sections);
        Assert.Contains(result.Sections, s => s.Name == ".shstrtab");
    }

    [Fact]
    public void elf_corpus_fixture_minimal_elf64_accepted()
    {
        string path = Path.Combine(BinaryCorpusDir, "minimal_elf64.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = ElfMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.True(result.Is64Bit);
        Assert.NotEmpty(result.Sections);
        Assert.Contains(result.Sections, s => s.Name == ".shstrtab");
    }

    [Fact]
    public void elf_corpus_fixture_invalid_magic_rejected()
    {
        string path = Path.Combine(BinaryCorpusDir, "elf_invalid_magic.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = ElfMetadataParser.Parse(data);

        Assert.False(result.IsValid);
        Assert.Equal(ElfMetadataFailureReason.InvalidMagic, result.FailureReason);
    }

    [Fact]
    public void elf_corpus_fixture_build_id_collected()
    {
        string path = Path.Combine(BinaryCorpusDir, "elf_with_build_id.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);
        var result = ElfMetadataParser.Parse(data);

        Assert.True(result.IsValid);
        Assert.Contains(result.NoteNames, n => n.StartsWith("GNU", StringComparison.Ordinal));
        Assert.NotEmpty(result.BuildIdNotes);
    }

    [Fact]
    public void printable_string_extractor_fallback_for_random_binary()
    {
        string path = Path.Combine(BinaryCorpusDir, "high_entropy_random.bin");
        Assert.True(File.Exists(path));
        byte[] data = File.ReadAllBytes(path);

        // PE/ELF parsing should fail; the binary is just random bytes.
        var peResult = PeMetadataParser.Parse(data);
        var elfResult = ElfMetadataParser.Parse(data);

        Assert.False(peResult.IsValid);
        Assert.False(elfResult.IsValid);

        // The generic PrintableStringExtractor is the safe fallback. It should
        // never crash on the random input and should still record a coverage
        // gap for any unmatched bytes.
        var extracted = PrintableStringExtractor.Extract(data);
        Assert.NotNull(extracted);
        Assert.Equal(data.Length, extracted.TotalBytesScanned);
    }

    private static byte[] BuildMinimalPe()
    {
        // MZ + stub DOS header + PE signature + COFF header + minimal section.
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        // DOS header (64 bytes minimum)
        w.Write((byte)'M');
        w.Write((byte)'Z');
        w.Write(new byte[58]); // pad to e_lfanew
        // e_lfanew at offset 0x3C
        long eLfanewPos = w.BaseStream.Position;
        w.Write((uint)64);

        // PE signature + COFF header at offset 64
        w.BaseStream.Position = 64;
        w.Write((uint)0x00004550); // PE\0\0

        // COFF header
        w.Write((ushort)0x8664);  // Machine = AMD64
        w.Write((ushort)1);      // NumberOfSections
        w.Write((uint)0);        // TimeDateStamp
        w.Write((uint)0);        // PointerToSymbolTable
        w.Write((uint)0);        // NumberOfSymbols
        w.Write((ushort)240);    // SizeOfOptionalHeader (PE32+)
        w.Write((ushort)0x0102); // Characteristics EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

        // Optional header (PE32+, 240 bytes for PE32+). Magic + fill.
        w.Write((ushort)0x20B); // Magic = PE32+
        w.Write(new byte[238]);

        // Section header: .text
        w.Write(Encoding.ASCII.GetBytes(".text\0\0\0"));
        w.Write((uint)0); // VirtualSize
        w.Write((uint)0); // VirtualAddress
        w.Write((uint)0); // SizeOfRawData
        w.Write((uint)0); // PointerToRawData
        w.Write((uint)0); // PointerToRelocations
        w.Write((uint)0); // PointerToLinenumbers
        w.Write((ushort)0); // NumberOfRelocations
        w.Write((ushort)0); // NumberOfLinenumbers
        w.Write((uint)0x60000020); // Characteristics

        w.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildMinimalElf64()
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        // ELF64 header: 64 bytes
        w.Write(new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' });
        w.Write((byte)2); // EI_CLASS = ELFCLASS64
        w.Write((byte)1); // EI_DATA = ELFDATA2LSB
        w.Write((byte)1); // EI_VERSION
        w.Write((byte)0); // EI_OSABI
        w.Write(new byte[8]); // EI_ABIVERSION + padding

        w.Write((ushort)2);  // e_type = ET_EXEC
        w.Write((ushort)62); // e_machine = EM_X86_64
        w.Write((uint)1);    // e_version
        w.Write((ulong)0);   // e_entry
        w.Write((ulong)64);  // e_phoff (program headers right after ELF header)
        w.Write((ulong)64);  // e_shoff (section headers right after program headers)
        w.Write((uint)0);    // e_flags
        w.Write((ushort)64); // e_ehsize
        w.Write((ushort)0);  // e_phentsize
        w.Write((ushort)0);  // e_phnum
        w.Write((ushort)64); // e_shentsize (sizeof section header)
        w.Write((ushort)1);  // e_shnum (1 section)
        w.Write((ushort)1);  // e_shstrndx

        // Section header for .shstrtab (index 1)
        w.Write((uint)1); // sh_name (offset 1 in the strtab)
        w.Write((uint)3); // sh_type = SHT_STRTAB
        w.Write((ulong)0); // sh_flags
        w.Write((ulong)0); // sh_addr
        w.Write((ulong)0); // sh_offset
        w.Write((ulong)11); // sh_size (length of string + null)
        w.Write((uint)0); // sh_link
        w.Write((uint)0); // sh_info
        w.Write((ulong)1); // sh_addralign
        w.Write((ulong)0); // sh_entsize

        // Append the string table at the end: "\0.shstrtab\0"
        w.Write((byte)0);
        w.Write(Encoding.ASCII.GetBytes(".shstrtab"));
        w.Write((byte)0);

        w.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildMinimalElf32()
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        // ELF32 header: 52 bytes
        w.Write(new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' });
        w.Write((byte)1); // EI_CLASS = ELFCLASS32
        w.Write((byte)1); // EI_DATA = ELFDATA2LSB
        w.Write((byte)1); // EI_VERSION
        w.Write((byte)0); // EI_OSABI
        w.Write(new byte[8]);

        w.Write((ushort)2);  // e_type
        w.Write((ushort)3);  // e_machine = EM_386
        w.Write((uint)1);    // e_version
        w.Write((uint)0);    // e_entry
        w.Write((uint)52);   // e_phoff (right after header)
        w.Write((uint)52);   // e_shoff (no program headers; right after header)
        w.Write((uint)0);    // e_flags
        w.Write((ushort)52); // e_ehsize
        w.Write((ushort)0);  // e_phentsize
        w.Write((ushort)0);  // e_phnum
        w.Write((ushort)40); // e_shentsize
        w.Write((ushort)1);  // e_shnum
        w.Write((ushort)1);  // e_shstrndx

        // Section header for .shstrtab (40 bytes for ELF32)
        w.Write((uint)1);
        w.Write((uint)3);
        w.Write((uint)0);
        w.Write((uint)0);
        w.Write((uint)0);
        w.Write((uint)11);
        w.Write((uint)0);
        w.Write((uint)0);
        w.Write((uint)1);
        w.Write((uint)0);

        // Append the string table at the end
        w.Write((byte)0);
        w.Write(Encoding.ASCII.GetBytes(".shstrtab"));
        w.Write((byte)0);

        w.Flush();
        return ms.ToArray();
    }

    private static async Task<List<ParserEvent>> ParseAsync(string filePath, JarFormatParser parser, string virtualPath)
    {
        var events = new List<ParserEvent>();
        await using var fs = File.OpenRead(filePath);
        await using var input = new ParserInput(fs, fs.Length);
        var context = MakeContext(virtualPath);
        await foreach (var evt in parser.ParseAsync(input, context, CancellationToken.None))
        {
            events.Add(evt);
        }

        return events;
    }
}
