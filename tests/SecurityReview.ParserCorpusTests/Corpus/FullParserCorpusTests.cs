using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Jvm;
using SecurityReview.Parsers.Models;
using SecurityReview.Parsers.Oci;
using SecurityReview.Parsers.OpenXml;
using SecurityReview.Parsers.Pdf;
using SecurityReview.Parsers.Structured;
using SecurityReview.Parsers.Text;
using Xunit;

namespace SecurityReview.ParserCorpusTests.Corpus;

/// <summary>
/// Full parser corpus tests: per-adapter coverage requirements
/// and full regression of all corpus cases.
/// </summary>
public sealed class FullParserCorpusTests
{
    private static string CorpusRoot => Path.Combine(
        Path.GetDirectoryName(typeof(FullParserCorpusTests).Assembly.Location)!,
        "Corpus");

    private static string ManifestPath => Path.Combine(CorpusRoot,
        "corpus-manifest.json");

    private static JsonDocument LoadManifestDoc()
    {
        Assert.True(File.Exists(ManifestPath),
            $"corpus-manifest.json not found at {ManifestPath}");
        return JsonDocument.Parse(File.ReadAllText(ManifestPath));
    }

    /// <summary>Parser adapters under test, keyed by ParserId.</summary>
    private static Dictionary<string, IFormatParser> BuildParserMap() =>
        new IFormatParser[]
        {
            new TextFormatParser(),
            new XmlFormatParser(),
            new JsonFormatParser(),
            new YamlFormatParser(),
            new CsvFormatParser(),
            new OpenXmlFormatParser(),
            new PdfFormatParser(),
            new ZipFormatParser(),
            new TarFormatParser(),
            new GZipFormatParser(),
            new JarFormatParser(),
            new ModelFormatParser(),
            new DockerArchiveParser(),
            new OciLayerParser(),
        }.ToDictionary(p => p.ParserId);

    /// <summary>Parsers that support encrypted file detection.</summary>
    private static readonly HashSet<string> EncryptionParsers = new(StringComparer.Ordinal)
    {
        "zip", "openxml", "pdf",
    };

    // ── Per-adapter coverage checks ─────────────────────────

    [Fact]
    public void at_least_one_covered_case_per_adapter()
    {
        using var manifest = LoadManifestDoc();
        var adapterCases = GroupByParser(manifest);

        var missing = new List<string>();
        foreach ((string parserId, var cases) in adapterCases)
        {
            if (parserId == "none") continue;

            bool hasCovered = cases.Any(c =>
                c.Coverage == "Covered");
            if (!hasCovered)
                missing.Add(parserId);
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void at_least_one_not_covered_case_per_adapter()
    {
        using var manifest = LoadManifestDoc();
        var adapterCases = GroupByParser(manifest);

        var missing = new List<string>();
        foreach ((string parserId, var cases) in adapterCases)
        {
            if (parserId == "none") continue;

            bool hasNotCovered = cases.Any(c =>
                c.Coverage == "NotCovered");
            if (!hasNotCovered)
                missing.Add(parserId);
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void at_least_one_corrupt_case_per_adapter()
    {
        using var manifest = LoadManifestDoc();
        var adapterCases = GroupByParser(manifest);

        var missing = new List<string>();
        foreach ((string parserId, var cases) in adapterCases)
        {
            if (parserId == "none") continue;

            bool hasCorrupt = cases.Any(c =>
                c.ExpectedGaps.Any(g =>
                    g.Reason == "Corrupt" || g.Reason == "DecodeUnreliable"));
            if (!hasCorrupt)
                missing.Add(parserId);
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void at_least_one_limit_case_per_adapter()
    {
        using var manifest = LoadManifestDoc();
        var adapterCases = GroupByParser(manifest);

        var missing = new List<string>();
        foreach ((string parserId, var cases) in adapterCases)
        {
            if (parserId == "none") continue;

            bool hasLimit = cases.Any(c =>
                c.ExpectedGaps.Any(g =>
                    g.Reason is "ArchiveLimit" or "ParserTimeout"
                        or "ParserMemory" or "ParserCrash"));
            if (!hasLimit)
                missing.Add(parserId);
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void at_least_one_encrypted_case_per_encryption_adapter()
    {
        using var manifest = LoadManifestDoc();
        var adapterCases = GroupByParser(manifest);

        var missing = new List<string>();
        foreach ((string parserId, var cases) in adapterCases)
        {
            if (!EncryptionParsers.Contains(parserId)) continue;

            bool hasEncrypted = cases.Any(c =>
                c.ExpectedGaps.Any(g => g.Reason == "Encrypted"));
            if (!hasEncrypted)
                missing.Add(parserId);
        }

        Assert.Empty(missing);
    }

    // ── Full regression ─────────────────────────────────────

    [Fact]
    public async Task full_regression_all_cases_produce_expected_events()
    {
        using var manifestDoc = LoadManifestDoc();
        var cases = ParseAllCases(manifestDoc);
        var parsers = BuildParserMap();

        var failures = new List<string>();

        foreach (CaseRecord rec in cases)
        {
            string fixturePath = Path.Combine(CorpusRoot, rec.FixturePath);

            if (!File.Exists(fixturePath))
            {
                failures.Add($"{rec.CaseId}: fixture not found");
                continue;
            }

            // Verify SHA-256.
            string actualSha256;
            long fileLength;
            using (var fs = File.OpenRead(fixturePath))
            {
                fileLength = fs.Length;
                byte[] hash = await SHA256.HashDataAsync(fs);
                actualSha256 = Convert.ToHexString(hash).ToLowerInvariant();
            }

            if (!string.Equals(actualSha256, rec.Sha256, StringComparison.Ordinal))
            {
                failures.Add($"{rec.CaseId}: SHA-256 mismatch");
                continue;
            }

            if (fileLength == 0)
            {
                if (rec.ExpectedChunks.Count != 0 || rec.ExpectedGaps.Count != 0)
                    failures.Add($"{rec.CaseId}: empty file produced unexpected events");
                continue;
            }

            // Check parser exists.
            if (!parsers.TryGetValue(rec.ExpectedParser, out IFormatParser? parser))
            {
                if (rec.ExpectedParser == "none")
                {
                    // Verify we get UnsupportedFormat gap.
                    // Probe to confirm no parser matches.
                    string ext = Path.GetExtension(rec.FixturePath);
                    FormatProbe probe;
                    using (var fs = File.OpenRead(fixturePath))
                    {
                        probe = await FormatSniffer.ProbeAsync(fs, ext, CancellationToken.None);
                    }

                    IFormatParser? anyParser = parsers.Values
                        .FirstOrDefault(p => p.CanParse(probe));
                    if (anyParser is not null)
                    {
                        failures.Add(
                            $"{rec.CaseId}: expected no parser, but '{anyParser.ParserId}' matches");
                    }
                    continue;
                }

                failures.Add($"{rec.CaseId}: unknown parser '{rec.ExpectedParser}'");
                continue;
            }

            // Run parser and compare.
            try
            {
                string? diff = await RunParserAndCompareAsync(
                    fixturePath, fileLength, parser, rec);
                if (diff is not null)
                    failures.Add($"{rec.CaseId}: {diff}");
            }
            catch (Exception ex)
            {
                // If we expected a Corrupt exception, that's a pass.
                bool expectedException = rec.ExpectedGaps.Any(g =>
                    g.Reason == "Corrupt" &&
                    g.DetailCode.StartsWith("exception:", StringComparison.Ordinal));
                if (expectedException &&
                    rec.ExpectedChunks.Count == 0)
                {
                    // Exception is expected.
                }
                else
                {
                    failures.Add($"{rec.CaseId}: unexpected exception {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        Assert.Empty(failures);
    }

    // ── Helpers ─────────────────────────────────────────────

    private sealed record CaseRecord(
        string CaseId, string FixturePath, string Sha256, string Format,
        string ExpectedParser, string ExpectedParserVersion,
        IReadOnlyList<ChunkRecord> ExpectedChunks,
        IReadOnlyList<GapRecord> ExpectedGaps,
        string Coverage);

    private sealed record ChunkRecord(
        string Label, long SourceStart, long SourceLength,
        string VirtualPath, string FormatId, string ContentKind, string? Encoding);

    private sealed record GapRecord(
        string Reason, string DetailCode, string? VirtualPath);

    private static List<CaseRecord> ParseAllCases(JsonDocument manifest)
    {
        var cases = new List<CaseRecord>();
        foreach (JsonElement c in manifest.RootElement.GetProperty("Cases")
           .EnumerateArray())
        {
            var chunks = new List<ChunkRecord>();
            foreach (JsonElement ch in c.GetProperty("ExpectedChunks").EnumerateArray())
            {
                chunks.Add(new ChunkRecord(
                    ch.GetProperty("Label").GetString()!,
                    ch.GetProperty("SourceStart").GetInt64(),
                    ch.GetProperty("SourceLength").GetInt64(),
                    ch.GetProperty("VirtualPath").GetString()!,
                    ch.GetProperty("FormatId").GetString()!,
                    ch.GetProperty("ContentKind").GetString()!,
                    ch.TryGetProperty("Encoding", out JsonElement enc) &&
                    enc.ValueKind != JsonValueKind.Null ? enc.GetString() : null));
            }

            var gaps = new List<GapRecord>();
            foreach (JsonElement g in c.GetProperty("ExpectedGaps").EnumerateArray())
            {
                gaps.Add(new GapRecord(
                    g.GetProperty("Reason").GetString()!,
                    g.GetProperty("DetailCode").GetString()!,
                    g.TryGetProperty("VirtualPath", out JsonElement vp) &&
                    vp.ValueKind != JsonValueKind.Null ? vp.GetString() : null));
            }

            cases.Add(new CaseRecord(
                c.GetProperty("CaseId").GetString()!,
                c.GetProperty("FixturePath").GetString()!,
                c.GetProperty("Sha256").GetString()!,
                c.GetProperty("Format").GetString()!,
                c.GetProperty("ExpectedParser").GetString()!,
                c.GetProperty("ExpectedParserVersion").GetString()!,
                chunks, gaps,
                c.GetProperty("Coverage").GetString()!));
        }

        return cases;
    }

    private static Dictionary<string, List<CaseRecord>> GroupByParser(
        JsonDocument manifest)
    {
        var groups = new Dictionary<string, List<CaseRecord>>();
        foreach (CaseRecord rec in ParseAllCases(manifest))
        {
            if (!groups.TryGetValue(rec.ExpectedParser, out var list))
            {
                list = new List<CaseRecord>();
                groups[rec.ExpectedParser] = list;
            }
            list.Add(rec);
        }
        return groups;
    }

    private static async Task<string?> RunParserAndCompareAsync(
        string fixturePath, long fileLength,
        IFormatParser parser, CaseRecord expected)
    {
        var actualChunks = new List<ChunkRecord>();
        var actualGaps = new List<GapRecord>();

        await using FileStream fs = File.OpenRead(fixturePath);
        var input = new ParserInput(fs, fileLength);
        var jobId = new JobId(Guid.NewGuid());
        var scanId = new ScanId(Guid.NewGuid());
        var limits = new ParseLimits(
            DateTimeOffset.UtcNow.AddMinutes(5), 5, 100_000, 50_000_000_000, 1_048_576);
        var context = new ParseContext(jobId, scanId, expected.FixturePath, limits);

        await foreach (ParserEvent evt in parser.ParseAsync(
           input, context, CancellationToken.None))
        {
            switch (evt)
            {
                case ParserEvent.ChunkProduced c:
                    byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(c.Chunk.Text);
                    byte[] labelHash = SHA256.HashData(textBytes);
                    string label = Convert.ToHexString(labelHash).ToLowerInvariant();
                    actualChunks.Add(new ChunkRecord(
                        label,
                        c.Chunk.SourceStart,
                        c.Chunk.SourceLength,
                        c.Chunk.VirtualPath,
                        c.Chunk.FormatId,
                        c.Chunk.ContentKind.ToString(),
                        c.Chunk.Encoding));
                    break;

                case ParserEvent.GapProduced g:
                    actualGaps.Add(new GapRecord(
                        g.Gap.Reason.ToString(),
                        g.Gap.DetailCode,
                        g.Gap.VirtualPath));
                    break;
            }
        }

        // Compare chunks.
        if (expected.ExpectedChunks.Count != actualChunks.Count)
        {
            return $"chunk count mismatch: expected {expected.ExpectedChunks.Count}, " +
                $"got {actualChunks.Count}";
        }

        for (int i = 0; i < expected.ExpectedChunks.Count; i++)
        {
            ChunkRecord exp = expected.ExpectedChunks[i];
            ChunkRecord act = actualChunks[i];

            if (exp.Label != act.Label)
                return $"chunk[{i}] label mismatch: {exp.Label} vs {act.Label}";
            if (exp.SourceStart != act.SourceStart)
                return $"chunk[{i}] sourceStart: {exp.SourceStart} vs {act.SourceStart}";
            if (exp.SourceLength != act.SourceLength)
                return $"chunk[{i}] sourceLength: {exp.SourceLength} vs {act.SourceLength}";
            if (exp.VirtualPath != act.VirtualPath)
                return $"chunk[{i}] virtualPath: '{exp.VirtualPath}' vs '{act.VirtualPath}'";
            if (exp.FormatId != act.FormatId)
                return $"chunk[{i}] formatId: {exp.FormatId} vs {act.FormatId}";
            if (exp.ContentKind != act.ContentKind)
                return $"chunk[{i}] contentKind: {exp.ContentKind} vs {act.ContentKind}";
            if (exp.Encoding != act.Encoding)
                return $"chunk[{i}] encoding: '{exp.Encoding}' vs '{act.Encoding}'";
        }

        // Compare gaps.
        if (expected.ExpectedGaps.Count != actualGaps.Count)
        {
            return $"gap count mismatch: expected {expected.ExpectedGaps.Count}, " +
                $"got {actualGaps.Count}";
        }

        for (int i = 0; i < expected.ExpectedGaps.Count; i++)
        {
            GapRecord exp = expected.ExpectedGaps[i];
            GapRecord act = actualGaps[i];

            if (exp.Reason != act.Reason)
                return $"gap[{i}] reason: '{exp.Reason}' vs '{act.Reason}'";
            if (exp.DetailCode != act.DetailCode)
                return $"gap[{i}] detailCode: '{exp.DetailCode}' vs '{act.DetailCode}'";
            if (exp.VirtualPath != act.VirtualPath)
                return $"gap[{i}] virtualPath: '{exp.VirtualPath}' vs '{act.VirtualPath}'";
        }

        return null; // All good.
    }
}
