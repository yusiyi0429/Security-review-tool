using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.CorpusTool.Model;
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

namespace SecurityReview.CorpusTool.Commands;

/// <summary>
/// Corpus verification command. Two modes:
/// <list type="bullet">
///   <item><b>record</b> — runs all parsers on corpus fixtures and writes expected events to a manifest.</item>
///   <item><b>verify</b> — loads a manifest, re-runs all cases, and compares actual events against expectations.</item>
/// </list>
/// </summary>
public static class VerifyParserCorpusCommand
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        TypeInfoResolver = CorpusJsonContext.Default,
        WriteIndented = true,
    };

    private static readonly JsonSerializerOptions ResultJsonOptions = new()
    {
        TypeInfoResolver = CorpusJsonContext.Default,
        WriteIndented = true,
    };

    /// <summary>All parser adapters available for corpus verification.</summary>
    private static IFormatParser[] BuildParserRegistry() =>
    [
        // Text / structured
        new TextFormatParser(),
        new XmlFormatParser(),
        new JsonFormatParser(),
        new YamlFormatParser(),
        new CsvFormatParser(),

        // Document formats
        new OpenXmlFormatParser(),
        new PdfFormatParser(),

        // Archives
        new ZipFormatParser(),
        new TarFormatParser(),
        new GZipFormatParser(),

        // JVM
        new JarFormatParser(),

        // Models
        new ModelFormatParser(),

        // OCI / containers
        new DockerArchiveParser(),
        new OciLayerParser(),
    ];

    public static async Task<int> RunAsync(
        string[] args, CancellationToken cancellationToken = default)
    {
        bool record = false;
        string? root = null;
        string? manifestPath = null;
        string? outputPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--record":
                    record = true;
                    break;
                case "--root" when i + 1 < args.Length:
                    root = args[++i];
                    break;
                case "--manifest" when i + 1 < args.Length:
                    manifestPath = args[++i];
                    break;
                case "--output" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
            }
        }

        if (record)
        {
            if (root is null || !Directory.Exists(root) || outputPath is null)
            {
                await Console.Error.WriteLineAsync(
                    "Usage: verify-parser-corpus --record --root <corpus-dir> --output <manifest.json>");
                return 2;
            }

            return await RecordAsync(root, outputPath, cancellationToken);
        }

        if (manifestPath is null || !File.Exists(manifestPath) || outputPath is null)
        {
            await Console.Error.WriteLineAsync(
                "Usage: verify-parser-corpus --manifest <manifest.json> --output <results.json>");
            return 2;
        }

        return await VerifyAsync(manifestPath, outputPath, cancellationToken);
    }

    // ────────────────────────────────────────────────────────
    //  Record mode
    // ────────────────────────────────────────────────────────

    private static async Task<int> RecordAsync(
        string root, string outputPath, CancellationToken ct)
    {
        string fullRoot = Path.GetFullPath(root);
        string[] files = Directory.GetFiles(fullRoot, "*.*", SearchOption.AllDirectories);

        var parsers = BuildParserRegistry();
        var cases = new List<CorpusCase>();

        string? rootDirName = Path.GetFileName(fullRoot.TrimEnd(Path.DirectorySeparatorChar));

        foreach (string filePath in files)
        {
            string relativePath = Path.GetRelativePath(fullRoot, filePath)
                .Replace('\\', '/');

            // Skip scripts, schemas, and the manifest itself.
            if (ShouldSkipFile(relativePath))
                continue;

            ct.ThrowIfCancellationRequested();

            CorpusCase? corpusCase = await RecordCaseAsync(
                fullRoot, relativePath, filePath, parsers, ct);

            if (corpusCase is not null)
                cases.Add(corpusCase);
        }

        // Sort by case ID for deterministic output.
        cases.Sort((a, b) => string.CompareOrdinal(a.CaseId, b.CaseId));

        var manifest = new CorpusManifest
        {
            Version = "1.0",
            Cases = cases,
        };

        string? outputDir = Path.GetDirectoryName(outputPath);
        if (outputDir is not null)
            Directory.CreateDirectory(outputDir);

        string json = JsonSerializer.Serialize(manifest, ManifestJsonOptions);
        await File.WriteAllTextAsync(outputPath, json, ct);

        await Console.Out.WriteLineAsync(
            $"Recorded {cases.Count} corpus cases to {outputPath}");

        return 0;
    }

    private static async Task<CorpusCase?> RecordCaseAsync(
        string fullRoot, string relativePath, string filePath,
        IFormatParser[] parsers, CancellationToken ct)
    {
        // Compute SHA-256.
        string sha256;
        long fileLength;
        try
        {
            await using FileStream fs = File.OpenRead(filePath);
            fileLength = fs.Length;
            byte[] hash = await SHA256.HashDataAsync(fs, ct);
            sha256 = Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(
                $"WARNING: Cannot hash {relativePath}: {ex.Message}");
            return null;
        }

        if (fileLength == 0)
        {
            // Empty files: record with no chunks/no gaps, NotCovered.
            return new CorpusCase
            {
                CaseId = MakeCaseId(relativePath),
                FixturePath = relativePath,
                Sha256 = sha256,
                Format = "empty",
                ExpectedParser = "none",
                ExpectedParserVersion = "0.0",
                ExpectedChunks = [],
                ExpectedGaps = [],
                MaxDurationMs = 5_000,
                MaxMemoryMb = 64,
                Coverage = "NotCovered",
            };
        }

        // Run through parsers.
        string extensionHint = Path.GetExtension(relativePath);
        FormatProbe probe;
        try
        {
            await using FileStream fs = File.OpenRead(filePath);
            probe = await FormatSniffer.ProbeAsync(fs, extensionHint, ct);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(
                $"WARNING: Cannot probe {relativePath}: {ex.Message}");
            return null;
        }

        IFormatParser? parser = parsers.FirstOrDefault(p => p.CanParse(probe));

        string format = probe.Format.FormatId;
        string parserId = parser?.ParserId ?? "none";
        string parserVersion = parser?.ParserVersion.ToString() ?? "0.0";

        var chunks = new List<ExpectedChunk>();
        var gaps = new List<ExpectedGap>();
        bool hadChunks = false;
        bool hadGaps = false;

        try
        {
            await using FileStream fs = File.OpenRead(filePath);
            var input = new ParserInput(fs, fileLength);
            var jobId = new JobId(Guid.NewGuid());
            var scanId = new ScanId(Guid.NewGuid());
            var limits = Application.Scans.ScanScheduler.CreateOrdinaryLimits(
                DateTimeOffset.UtcNow);
            var context = new ParseContext(jobId, scanId, relativePath, limits);

            if (parser is not null)
            {
                await foreach (ParserEvent evt in parser.ParseAsync(input, context, ct))
                {
                    switch (evt)
                    {
                        case ParserEvent.ChunkProduced c:
                            chunks.Add(ChunkToExpected(c.Chunk));
                            hadChunks = true;
                            break;
                        case ParserEvent.GapProduced g:
                            gaps.Add(GapToExpected(g.Gap));
                            hadGaps = true;
                            break;
                    }
                }
            }
            else
            {
                // Record unsupported format as a gap.
                gaps.Add(new ExpectedGap
                {
                    Reason = "UnsupportedFormat",
                    DetailCode = $"no_parser:{format}",
                    VirtualPath = null,
                });
                hadGaps = true;
            }
        }
        catch (Exception ex)
        {
            gaps.Add(new ExpectedGap
            {
                Reason = "Corrupt",
                DetailCode = $"exception:{ex.GetType().Name}",
                VirtualPath = null,
            });
            hadGaps = true;
        }

        string coverage = DetermineCoverage(hadChunks, hadGaps);

        return new CorpusCase
        {
            CaseId = MakeCaseId(relativePath),
            FixturePath = relativePath,
            Sha256 = sha256,
            Format = format,
            ExpectedParser = parserId,
            ExpectedParserVersion = parserVersion,
            ExpectedChunks = chunks,
            ExpectedGaps = gaps,
            MaxDurationMs = 30_000,
            MaxMemoryMb = 512,
            Coverage = coverage,
        };
    }

    // ────────────────────────────────────────────────────────
    //  Verify mode
    // ────────────────────────────────────────────────────────

    private static async Task<int> VerifyAsync(
        string manifestPath, string outputPath, CancellationToken ct)
    {
        // Load manifest.
        string manifestJson = await File.ReadAllTextAsync(manifestPath, ct);
        CorpusManifest? manifest = JsonSerializer.Deserialize<CorpusManifest>(
            manifestJson, ManifestJsonOptions);

        if (manifest is null)
        {
            await Console.Error.WriteLineAsync("ERROR: Failed to parse manifest.");
            return 2;
        }

        // Resolve corpus root as the directory containing the manifest.
        string corpusRoot = Path.GetFullPath(
            Path.GetDirectoryName(manifestPath)!);

        var parsers = BuildParserRegistry();
        var results = new List<CaseResult>();
        int passed = 0, failed = 0, skipped = 0;

        foreach (CorpusCase expected in manifest.Cases)
        {
            ct.ThrowIfCancellationRequested();

            string fixturePath = Path.GetFullPath(
                Path.Combine(corpusRoot, expected.FixturePath));

            if (!File.Exists(fixturePath))
            {
                skipped++;
                results.Add(new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "skip",
                    Detail = $"Fixture not found: {fixturePath}",
                });
                continue;
            }

            var sw = Stopwatch.StartNew();
            try
            {
                CaseResult result = await VerifyCaseAsync(
                    expected, fixturePath, parsers, ct);
                result = result with { DurationMs = sw.ElapsedMilliseconds };

                results.Add(result);
                if (result.Result == "pass") passed++;
                else failed++;
            }
            catch (Exception ex)
            {
                failed++;
                results.Add(new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "fail",
                    DurationMs = sw.ElapsedMilliseconds,
                    Detail = $"Unhandled exception: {ex.Message}",
                });
            }
        }

        var corpusResult = new CorpusResult
        {
            TotalCases = manifest.Cases.Count,
            Passed = passed,
            Failed = failed,
            Skipped = skipped,
            Cases = results,
        };

        string? outputDir = Path.GetDirectoryName(outputPath);
        if (outputDir is not null)
            Directory.CreateDirectory(outputDir);

        string resultJson = JsonSerializer.Serialize(corpusResult, ResultJsonOptions);
        await File.WriteAllTextAsync(outputPath, resultJson, ct);

        await Console.Out.WriteLineAsync(
            $"Verify: {passed} passed, {failed} failed, {skipped} skipped of {manifest.Cases.Count} total");

        return failed == 0 ? 0 : 1;
    }

    private static async Task<CaseResult> VerifyCaseAsync(
        CorpusCase expected, string fixturePath,
        IFormatParser[] parsers, CancellationToken ct)
    {
        // Verify SHA-256.
        string actualSha256;
        long fileLength;
        await using (FileStream fs = File.OpenRead(fixturePath))
        {
            fileLength = fs.Length;
            byte[] hash = await SHA256.HashDataAsync(fs, ct);
            actualSha256 = Convert.ToHexString(hash).ToLowerInvariant();
        }

        if (!string.Equals(actualSha256, expected.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"SHA-256 mismatch: expected {expected.Sha256}, got {actualSha256}",
            };
        }

        if (fileLength == 0)
        {
            // Empty file: just verify no chunks/gaps.
            if (expected.ExpectedChunks.Count != 0 || expected.ExpectedGaps.Count != 0)
            {
                return new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "fail",
                    Detail = "Empty file produced unexpected events",
                };
            }
            return new CaseResult { CaseId = expected.CaseId, Result = "pass" };
        }

        // Probe and select parser.
        string extensionHint = Path.GetExtension(expected.FixturePath);
        FormatProbe probe;
        await using (FileStream fsProbe = File.OpenRead(fixturePath))
        {
            probe = await FormatSniffer.ProbeAsync(fsProbe, extensionHint, ct);
        }

        IFormatParser? parser = parsers.FirstOrDefault(p => p.CanParse(probe));
        string actualParserId = parser?.ParserId ?? "none";

        if (actualParserId != expected.ExpectedParser)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Parser mismatch: expected {expected.ExpectedParser}, got {actualParserId}",
            };
        }

        // Collect actual events.
        var actualChunks = new List<ExpectedChunk>();
        var actualGaps = new List<ExpectedGap>();

        try
        {
            await using FileStream fs = File.OpenRead(fixturePath);
            var input = new ParserInput(fs, fileLength);
            var jobId = new JobId(Guid.NewGuid());
            var scanId = new ScanId(Guid.NewGuid());
            var limits = Application.Scans.ScanScheduler.CreateOrdinaryLimits(
                DateTimeOffset.UtcNow);
            var context = new ParseContext(jobId, scanId, expected.FixturePath, limits);

            if (parser is not null)
            {
                await foreach (ParserEvent evt in parser.ParseAsync(input, context, ct))
                {
                    switch (evt)
                    {
                        case ParserEvent.ChunkProduced c:
                            actualChunks.Add(ChunkToExpected(c.Chunk));
                            break;
                        case ParserEvent.GapProduced g:
                            actualGaps.Add(GapToExpected(g.Gap));
                            break;
                    }
                }
            }
            else
            {
                actualGaps.Add(new ExpectedGap
                {
                    Reason = "UnsupportedFormat",
                    DetailCode = $"no_parser:{probe.Format.FormatId}",
                    VirtualPath = null,
                });
            }
        }
        catch (Exception ex)
        {
            actualGaps.Add(new ExpectedGap
            {
                Reason = "Corrupt",
                DetailCode = $"exception:{ex.GetType().Name}",
                VirtualPath = null,
            });
        }

        // Compare chunks.
        if (expected.ExpectedChunks.Count != actualChunks.Count)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Chunk count mismatch: expected {expected.ExpectedChunks.Count}, got {actualChunks.Count}",
            };
        }

        for (int i = 0; i < expected.ExpectedChunks.Count; i++)
        {
            string? diff = DiffChunks(expected.ExpectedChunks[i], actualChunks[i]);
            if (diff is not null)
            {
                return new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "fail",
                    Detail = $"Chunk[{i}] mismatch: {diff}",
                };
            }
        }

        // Compare gaps.
        if (expected.ExpectedGaps.Count != actualGaps.Count)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Gap count mismatch: expected {expected.ExpectedGaps.Count}, got {actualGaps.Count}",
            };
        }

        for (int i = 0; i < expected.ExpectedGaps.Count; i++)
        {
            string? diff = DiffGaps(expected.ExpectedGaps[i], actualGaps[i]);
            if (diff is not null)
            {
                return new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "fail",
                    Detail = $"Gap[{i}] mismatch: {diff}",
                };
            }
        }

        return new CaseResult { CaseId = expected.CaseId, Result = "pass" };
    }

    // ────────────────────────────────────────────────────────
    //  Helpers
    // ────────────────────────────────────────────────────────

    private static string MakeCaseId(string relativePath)
    {
        // Convert "Archives/traversal.zip" → "archives/traversal_zip"
        string dir = Path.GetDirectoryName(relativePath) ?? "";
        string name = Path.GetFileNameWithoutExtension(relativePath);
        string ext = Path.GetExtension(relativePath).TrimStart('.');

        string path = string.IsNullOrEmpty(dir)
            ? name
            : $"{dir}/{name}";

        if (!string.IsNullOrEmpty(ext))
            path = $"{path}_{ext}";

        return path.Replace('\\', '/').ToLowerInvariant();
    }

    private static bool ShouldSkipFile(string relativePath)
    {
        // Skip scripts, schemas, the manifest itself, and hidden files.
        string lower = relativePath.ToLowerInvariant();
        string name = Path.GetFileName(relativePath);

        if (name.StartsWith('.'))
            return true;
        if (lower.EndsWith(".sh", StringComparison.Ordinal) ||
            lower.EndsWith(".py", StringComparison.Ordinal) ||
            lower.EndsWith(".ps1", StringComparison.Ordinal))
            return true;
        if (lower.EndsWith(".schema.json", StringComparison.Ordinal))
            return true;
        if (lower.EndsWith("corpus-manifest.json", StringComparison.Ordinal))
            return true;
        if (name == "oci-layout")
            return true;

        return false;
    }

    private static ExpectedChunk ChunkToExpected(ContentChunk chunk)
    {
        // HMAC canary: SHA-256 of chunk text.
        byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(chunk.Text);
        byte[] labelHash = SHA256.HashData(textBytes);
        string label = Convert.ToHexString(labelHash).ToLowerInvariant();

        return new ExpectedChunk
        {
            Label = label,
            SourceStart = chunk.SourceStart,
            SourceLength = chunk.SourceLength,
            VirtualPath = chunk.VirtualPath,
            FormatId = chunk.FormatId,
            ContentKind = chunk.ContentKind.ToString(),
            Encoding = chunk.Encoding,
        };
    }

    private static ExpectedGap GapToExpected(CoverageGap gap)
    {
        return new ExpectedGap
        {
            Reason = gap.Reason.ToString(),
            DetailCode = gap.DetailCode,
            VirtualPath = gap.VirtualPath,
        };
    }

    private static string? DiffChunks(ExpectedChunk expected, ExpectedChunk actual)
    {
        if (!string.Equals(expected.Label, actual.Label, StringComparison.Ordinal))
            return $"label: expected {expected.Label}, got {actual.Label}";
        if (expected.SourceStart != actual.SourceStart)
            return $"sourceStart: expected {expected.SourceStart}, got {actual.SourceStart}";
        if (expected.SourceLength != actual.SourceLength)
            return $"sourceLength: expected {expected.SourceLength}, got {actual.SourceLength}";
        if (!string.Equals(expected.VirtualPath, actual.VirtualPath, StringComparison.Ordinal))
            return $"virtualPath: expected '{expected.VirtualPath}', got '{actual.VirtualPath}'";
        if (!string.Equals(expected.FormatId, actual.FormatId, StringComparison.Ordinal))
            return $"formatId: expected '{expected.FormatId}', got '{actual.FormatId}'";
        if (!string.Equals(expected.ContentKind, actual.ContentKind, StringComparison.Ordinal))
            return $"contentKind: expected '{expected.ContentKind}', got '{actual.ContentKind}'";
        if (!string.Equals(expected.Encoding, actual.Encoding, StringComparison.Ordinal))
            return $"encoding: expected '{expected.Encoding}', got '{actual.Encoding}'";
        return null;
    }

    private static string? DiffGaps(ExpectedGap expected, ExpectedGap actual)
    {
        if (!string.Equals(expected.Reason, actual.Reason, StringComparison.Ordinal))
            return $"reason: expected '{expected.Reason}', got '{actual.Reason}'";
        if (!string.Equals(expected.DetailCode, actual.DetailCode, StringComparison.Ordinal))
            return $"detailCode: expected '{expected.DetailCode}', got '{actual.DetailCode}'";
        if (!string.Equals(expected.VirtualPath, actual.VirtualPath, StringComparison.Ordinal))
            return $"virtualPath: expected '{expected.VirtualPath}', got '{actual.VirtualPath}'";
        return null;
    }

    private static string DetermineCoverage(bool hadChunks, bool hadGaps)
    {
        if (hadChunks && !hadGaps) return "Covered";
        if (hadChunks) return "Partial";
        return "NotCovered";
    }
}
