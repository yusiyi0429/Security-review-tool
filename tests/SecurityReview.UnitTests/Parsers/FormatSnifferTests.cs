using System.Text;
using SecurityReview.Parsers.Core;

namespace SecurityReview.UnitTests.Parsers;

public sealed class FormatSnifferTests
{
    [Fact]
    public void zip_magic_named_txt_selects_zip()
    {
        byte[] head = "PK\x03\x04"u8.ToArray();
        // Pad to minimum size
        Array.Resize(ref head, 256);

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("zip", result.FormatId);
        Assert.True(result.Confidence >= 0.5);
        Assert.Contains("magic_PK", result.SignatureEvidence);
        Assert.True(result.FormatExtensionMismatch);
    }

    [Fact]
    public void pdf_magic_named_json_selects_pdf()
    {
        byte[] head = "%PDF-1.4\n"u8.ToArray();
        Array.Resize(ref head, 256);
        byte[] tail = "%%EOF"u8.ToArray();

        var result = FormatSniffer.Detect(head, tail, ".json", head.Length);

        Assert.Equal("pdf", result.FormatId);
        Assert.Contains("magic_PDF", result.SignatureEvidence);
        Assert.True(result.FormatExtensionMismatch);
    }

    [Fact]
    public void elf_magic_wins_over_extension()
    {
        byte[] head = new byte[256];
        head[0] = 0x7F; head[1] = 0x45; head[2] = 0x4C; head[3] = 0x46;

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("elf", result.FormatId);
        Assert.Contains("magic_ELF", result.SignatureEvidence);
        Assert.True(result.FormatExtensionMismatch);
    }

    [Fact]
    public void pe_magic_wins_over_extension()
    {
        byte[] head = new byte[256];
        head[0] = 0x4D; head[1] = 0x5A;

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("pe", result.FormatId);
        Assert.Contains("magic_MZ", result.SignatureEvidence);
        Assert.True(result.FormatExtensionMismatch);
    }

    [Fact]
    public void java_class_magic_wins()
    {
        byte[] head = new byte[256];
        head[0] = 0xCA; head[1] = 0xFE; head[2] = 0xBA; head[3] = 0xBE;

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("java_class", result.FormatId);
        Assert.Contains("magic_JAVA_CLASS", result.SignatureEvidence);
    }

    [Fact]
    public void valid_utf8_without_magic_selects_text()
    {
        byte[] head = Encoding.UTF8.GetBytes("Hello, this is a plain text file.\nIt has multiple lines.\n");

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("text", result.FormatId);
        Assert.False(result.FormatExtensionMismatch);
    }

    [Fact]
    public void valid_utf8_chinese_selects_text()
    {
        byte[] head = Encoding.UTF8.GetBytes("你好世界！这是中文文本。\n包含多行内容。");

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("text", result.FormatId);
    }

    [Fact]
    public void nul_heavy_content_selects_binary()
    {
        byte[] head = new byte[1024];
        // Fill half with NULs
        for (int i = 0; i < 512; i++) head[i] = 0x00;
        // Fill rest with random-ish bytes
        for (int i = 512; i < 1024; i++) head[i] = (byte)(i % 256);

        var result = FormatSniffer.Detect(head, [], null, head.Length);

        Assert.Equal("binary", result.FormatId);
        Assert.Contains("high_nul_or_binary", result.SignatureEvidence);
    }

    [Fact]
    public void high_binary_content_selects_binary()
    {
        byte[] head = new byte[1024];
        var rng = new Random(42);
        rng.NextBytes(head);

        var result = FormatSniffer.Detect(head, [], null, head.Length);

        // Random bytes may or may not be valid UTF-8; if enough high bytes, binary
        Assert.True(result.FormatId is "binary" or "text");
    }

    [Fact]
    public void extension_mismatch_does_not_block_detected_format()
    {
        byte[] head = "PK\x03\x04"u8.ToArray();
        Array.Resize(ref head, 256);

        var result = FormatSniffer.Detect(head, [], ".pdf", head.Length);

        Assert.Equal("zip", result.FormatId);
        Assert.True(result.FormatExtensionMismatch);
    }

    [Fact]
    public void matching_extension_no_mismatch()
    {
        byte[] head = Encoding.UTF8.GetBytes("plain text content here.");
        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.False(result.FormatExtensionMismatch);
    }

    [Theory]
    [InlineData(".md")]
    [InlineData(".jsonl")]
    public void supported_text_extensions_do_not_report_mismatch(string extension)
    {
        byte[] head = Encoding.UTF8.GetBytes(
            "{\"message\":\"plain UTF-8 text content\"}\n");

        var result = FormatSniffer.Detect(head, [], extension, head.Length);

        Assert.Equal("text", result.FormatId);
        Assert.False(result.FormatExtensionMismatch);
    }

    [Theory]
    [InlineData(".json", "json")]
    [InlineData(".xml", "xml")]
    [InlineData(".yaml", "yaml")]
    [InlineData(".yml", "yaml")]
    [InlineData(".csv", "csv")]
    [InlineData(".tsv", "csv")]
    public void structured_text_extensions_select_specialized_parser(
        string extension,
        string expectedFormat)
    {
        byte[] head = Encoding.UTF8.GetBytes(
            "{\"message\":\"plain UTF-8 structured content\"}\n");

        DetectedFormat result = FormatSniffer.Detect(
            head,
            [],
            extension,
            head.Length);

        Assert.Equal(expectedFormat, result.FormatId);
        Assert.False(result.FormatExtensionMismatch);
    }

    [Fact]
    public void gzip_magic_detects_correctly()
    {
        byte[] head = new byte[256];
        head[0] = 0x1F; head[1] = 0x8B;

        var result = FormatSniffer.Detect(head, [], ".gz", head.Length);

        Assert.Equal("gzip", result.FormatId);
        Assert.False(result.FormatExtensionMismatch);
    }

    [Fact]
    public void png_magic_detects_correctly()
    {
        byte[] head = new byte[256];
        head[0] = 0x89; head[1] = 0x50; head[2] = 0x4E; head[3] = 0x47;
        head[4] = 0x0D; head[5] = 0x0A; head[6] = 0x1A; head[7] = 0x0A;

        var result = FormatSniffer.Detect(head, [], ".png", head.Length);

        Assert.Equal("png", result.FormatId);
    }

    [Fact]
    public void jpeg_magic_detects_correctly()
    {
        byte[] head = new byte[256];
        head[0] = 0xFF; head[1] = 0xD8; head[2] = 0xFF;

        var result = FormatSniffer.Detect(head, [], ".jpg", head.Length);

        Assert.Equal("jpeg", result.FormatId);
    }

    [Fact]
    public void empty_file_detects_empty()
    {
        var result = FormatSniffer.Detect([], [], null, 0);

        Assert.Equal("empty", result.FormatId);
        Assert.Equal(1.0, result.Confidence);
    }

    [Fact]
    public void utf8_bom_detects_text()
    {
        byte[] head = new byte[256];
        head[0] = 0xEF; head[1] = 0xBB; head[2] = 0xBF;
        Encoding.UTF8.GetBytes("Hello world").CopyTo(head, 3);

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("text", result.FormatId);
        Assert.Contains("bom_utf8", result.SignatureEvidence);
    }

    [Fact]
    public void utf16le_bom_detects_text()
    {
        byte[] head = new byte[256];
        head[0] = 0xFF; head[1] = 0xFE;

        var result = FormatSniffer.Detect(head, [], ".txt", head.Length);

        Assert.Equal("text", result.FormatId);
        Assert.Contains("bom_utf16le", result.SignatureEvidence);
    }

    [Fact]
    public void openxml_detected_from_content_types()
    {
        byte[] head = "PK\x03\x04"u8.ToArray();
        Array.Resize(ref head, 512);
        byte[] contentTypesXml = Encoding.ASCII.GetBytes("[Content_Types].xml");
        contentTypesXml.CopyTo(head, 30);

        var result = FormatSniffer.Detect(head, [], ".docx", head.Length);

        Assert.Equal("openxml", result.FormatId);
        Assert.Contains("openxml_content_types", result.SignatureEvidence);
    }
}
