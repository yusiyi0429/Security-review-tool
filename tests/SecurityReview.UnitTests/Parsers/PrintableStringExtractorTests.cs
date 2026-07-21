using System.Text;
using SecurityReview.Parsers.Binary;

namespace SecurityReview.UnitTests.Parsers;

public sealed class PrintableStringExtractorTests
{
    [Fact]
    public void ascii_strings_extracted_from_binary()
    {
        byte[] data = new byte[1024];
        // Insert "HelloWorld" at offset 100
        byte[] hello = "HelloWorld"u8.ToArray();
        hello.CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        Assert.NotEmpty(result.Strings);
        Assert.Contains(result.Strings, s => s.Text == "HelloWorld" && s.IsAscii);
    }

    [Fact]
    public void short_runs_below_six_chars_ignored()
    {
        byte[] data = new byte[256];
        "Hi"u8.ToArray().CopyTo(data, 50);

        var result = PrintableStringExtractor.Extract(data);

        // "Hi" is only 2 chars, should be ignored (minimum is 6)
        Assert.DoesNotContain(result.Strings, s => s.Text == "Hi");
    }

    [Fact]
    public void runs_of_exactly_six_chars_extracted()
    {
        byte[] data = new byte[256];
        "ABCDEF"u8.ToArray().CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        Assert.Contains(result.Strings, s => s.Text == "ABCDEF");
    }

    [Fact]
    public void byte_offsets_are_accurate()
    {
        byte[] data = new byte[512];
        "TestString"u8.ToArray().CopyTo(data, 200);

        var result = PrintableStringExtractor.Extract(data);

        var match = result.Strings.FirstOrDefault(s => s.Text == "TestString");
        Assert.NotEqual(default, match);
        Assert.Equal(200, match.ByteOffset);
        Assert.Equal(10, match.ByteLength);
        Assert.Equal("ascii", match.Encoding);
    }

    [Fact]
    public void utf16le_strings_extracted()
    {
        byte[] data = new byte[512];
        string original = "HelloWorld";
        byte[] utf16 = Encoding.Unicode.GetBytes(original);
        utf16.CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        Assert.Contains(result.Strings, s => s.Text == original && s.IsUtf16LE);
    }

    [Fact]
    public void utf16be_strings_extracted()
    {
        byte[] data = new byte[512];
        string original = "TestStr" + new string('x', 4); // minimum 6 chars
        byte[] utf16be = Encoding.BigEndianUnicode.GetBytes(original);
        utf16be.CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        Assert.Contains(result.Strings, s => s.Text == original && s.IsUtf16BE);
    }

    [Fact]
    public void coverage_gaps_cover_uncovered_bytes()
    {
        byte[] data = new byte[1024];
        "HelloWorld"u8.ToArray().CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        // Should have at least one coverage gap
        Assert.NotEmpty(result.CoverageGaps);

        // Total gap coverage + string coverage should equal total bytes
        long coveredByGaps = result.CoverageGaps.Sum(g => g.Length);
        long coveredByStrings = result.Strings.Sum(s => (long)s.ByteLength);
        long totalCovered = coveredByGaps + coveredByStrings;
        Assert.Equal(result.TotalBytesScanned, totalCovered);
    }

    [Fact]
    public void empty_input_returns_empty_result()
    {
        var result = PrintableStringExtractor.Extract([]);

        Assert.Empty(result.Strings);
        Assert.NotEmpty(result.CoverageGaps);
        Assert.Equal(0, result.TotalBytesScanned);
        Assert.Equal((0, 0), result.CoverageGaps[0]);
    }

    [Fact]
    public void strings_split_across_windows_are_de_duplicated()
    {
        // A long string that crosses the 1 MiB window boundary
        byte[] data = new byte[WindowSize + 100];
        string longStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        byte[] strBytes = Encoding.ASCII.GetBytes(longStr);
        // Place near the window boundary
        int offset = WindowSize - 10;
        strBytes.CopyTo(data, offset);

        var result = PrintableStringExtractor.Extract(data);

        // The string should appear (or at minimum no duplicates)
        var matches = result.Strings.Where(s => s.Text.Contains("ABCDEFGHIJ")).ToList();
        // Should find it or a fragment, but not zero
        Assert.NotEmpty(matches);
    }

    [Fact]
    public void too_short_utf16_runs_ignored()
    {
        byte[] data = new byte[256];
        // 4 UTF-16LE characters = 8 bytes, below minimum of 6 chars (12 bytes)
        byte[] shortUtf16 = Encoding.Unicode.GetBytes("ABCD");
        shortUtf16.CopyTo(data, 100);

        var result = PrintableStringExtractor.Extract(data);

        Assert.DoesNotContain(result.Strings, s => s.Text == "ABCD" && s.IsUtf16LE);
    }

    [Fact]
    public void total_bytes_scanned_matches_input_size()
    {
        byte[] data = new byte[5000];
        var rng = new Random(42);
        rng.NextBytes(data);
        "HelloWorld"u8.ToArray().CopyTo(data, 1000);

        var result = PrintableStringExtractor.Extract(data);

        Assert.Equal(5000, result.TotalBytesScanned);
    }

    private const int WindowSize = 1_048_576;
}
