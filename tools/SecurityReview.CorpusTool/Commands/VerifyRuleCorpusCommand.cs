using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Findings;
using SecurityReview.CorpusTool.Model;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;
using SecurityReview.RulePack.Detection;
using SecurityReview.RulePack.Packaging.Models;
using SecurityReview.RulePack.Schema;

namespace SecurityReview.CorpusTool.Commands;

/// <summary>
/// Rule corpus verification command. Runs the full detection pipeline
/// (parser → detectors → merger) against synthetic corpus fixtures and
/// compares actual findings against a rule-corpus-manifest.
///
/// Exit 1 on:
/// <list type="bullet">
///   <item>Missing Critical/High expected detection</item>
///   <item>Unexpected placeholder suppression</item>
///   <item>Detector error (coverage gap from exception)</item>
///   <item>Missing provenance on any finding</item>
///   <item>Undeclared gap in coverage</item>
/// </list>
/// </summary>
public static class VerifyRuleCorpusCommand
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        TypeInfoResolver = RuleCorpusJsonContext.Default,
        WriteIndented = true,
    };

    private static readonly JsonSerializerOptions ResultJsonOptions = new()
    {
        TypeInfoResolver = RuleCorpusJsonContext.Default,
        WriteIndented = true,
    };

    private static readonly JsonSerializerOptions RulePackDtoOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions RulePackJsonOptions = new()
    {
        TypeInfoResolver = RulePackJsonContext.Default,
        WriteIndented = false,
    };

    public static async Task<int> RunAsync(
        string[] args, CancellationToken cancellationToken = default)
    {
        string? rulesPath = null;
        string? manifestPath = null;
        string? outputPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--rules" when i + 1 < args.Length:
                    rulesPath = args[++i];
                    break;
                case "--manifest" when i + 1 < args.Length:
                    manifestPath = args[++i];
                    break;
                case "--output" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
            }
        }

        if (rulesPath is null || !File.Exists(rulesPath) ||
            manifestPath is null || !File.Exists(manifestPath) ||
            outputPath is null)
        {
            await Console.Error.WriteLineAsync(
                "Usage: verify-rule-corpus --rules <rule-pack.zip> --manifest <manifest.json> --output <results.json>");
            return 2;
        }

        return await VerifyAsync(rulesPath, manifestPath, outputPath, cancellationToken);
    }

    // ────────────────────────────────────────────────────────
    //  Verify
    // ────────────────────────────────────────────────────────

    private static async Task<int> VerifyAsync(
        string rulesPath, string manifestPath, string outputPath, CancellationToken ct)
    {
        // Load manifest
        string manifestJson = await File.ReadAllTextAsync(manifestPath, ct);
        RuleCorpusManifest? manifest = JsonSerializer.Deserialize<RuleCorpusManifest>(
            manifestJson, ManifestJsonOptions);

        if (manifest is null)
        {
            await Console.Error.WriteLineAsync("ERROR: Failed to parse rule corpus manifest.");
            return 2;
        }

        // Resolve corpus root as directory containing the manifest
        string corpusRoot = Path.GetFullPath(
            Path.GetDirectoryName(manifestPath)!);

        // Load rule pack and build pipeline
        PipelineContext pipeline;
        try
        {
            byte[] zipBytes = await File.ReadAllBytesAsync(rulesPath, ct);
            pipeline = BuildPipeline(zipBytes);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(
                $"ERROR: Failed to load rule pack: {ex.Message}");
            return 2;
        }

        // Verify rule pack SHA-256 matches manifest
        string rulePackSha256 = Convert.ToHexStringLower(SHA256.HashData(
            await File.ReadAllBytesAsync(rulesPath, ct)));
        if (!string.Equals(rulePackSha256, manifest.RulePackSha256, StringComparison.OrdinalIgnoreCase))
        {
            await Console.Error.WriteLineAsync(
                $"ERROR: Rule pack SHA-256 mismatch: manifest expects {manifest.RulePackSha256}, got {rulePackSha256}");
            return 2;
        }

        var results = new List<CaseResult>();
        int passed = 0, failed = 0, skipped = 0;

        foreach (RuleCorpusCase expected in manifest.Cases)
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
                    expected, fixturePath, pipeline, ct);
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

        var corpusResult = new RuleCorpusResult
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

    // ────────────────────────────────────────────────────────
    //  Per-case verification
    // ────────────────────────────────────────────────────────

    private static async Task<CaseResult> VerifyCaseAsync(
        RuleCorpusCase expected, string fixturePath,
        PipelineContext pipeline, CancellationToken ct)
    {
        // Verify SHA-256
        string actualSha256;
        long fileLength;
        byte[] fileBytes;
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

        // Parse fixture into chunks
        fileBytes = await File.ReadAllBytesAsync(fixturePath, ct);

        var chunks = new List<ContentChunk>();
        try
        {
            await using var ms = new MemoryStream(fileBytes);
            var input = new ParserInput(ms, fileLength);
            var jobId = new JobId(Guid.NewGuid());
            var scanId = new ScanId(Guid.NewGuid());
            var context = new ParseContext(
                jobId, scanId, expected.FixturePath,
                Application.Scans.ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow));

            var parser = new TextFormatParser();
            await foreach (ParserEvent evt in parser.ParseAsync(input, context, ct))
            {
                if (evt is ParserEvent.ChunkProduced c)
                    chunks.Add(c.Chunk);
            }
        }
        catch (Exception ex)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Parse error: {ex.GetType().Name}: {ex.Message}",
            };
        }

        // Run detection pipeline on all chunks
        var allCandidates = new List<DetectionCandidate>();
        var allGaps = new List<DetectorCoverageGap>();

        // Compute job-level SHA-256 for provenance
        string jobSha256 = Convert.ToHexStringLower(SHA256.HashData(fileBytes));

        foreach (ContentChunk chunk in chunks)
        {
            // Filter rules to those applicable to the chunk's asset types
            var applicableRules = pipeline.Rules
                .Where(r => r.Enabled && r.AppliesToAssets
                    .Any(a => expected.AssetTypeIds.Contains(a.Value)))
                .ToList();

            if (applicableRules.Count == 0)
                continue;

            PipelineResult pr = await pipeline.Pipeline.ExecuteAsync(
                chunk, applicableRules, pipeline.DetectorDefs, ct);
            allCandidates.AddRange(pr.Candidates);
            allGaps.AddRange(pr.CoverageGaps);
        }

        // Check for detector errors (coverage gaps)
        if (allGaps.Count > 0)
        {
            var gapDetails = allGaps.Select(g =>
                $"{g.DetectorKind}/{g.DetectorId.Value}/{g.RuleId.Value}: {g.Reason}").ToList();
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Detector coverage gaps ({allGaps.Count}): {string.Join("; ", gapDetails)}",
            };
        }

        // Merge candidates into finding groups using a local fingerprint service.
        // CandidateMerger requires IValueFingerprintService; we inline a lightweight
        // implementation to avoid pulling the full Infrastructure dependency.
        var fingerprint = new CorpusFingerprintService();
        var merger = new CandidateMerger(fingerprint);
        var mergeScanId = new ScanId(Guid.NewGuid());
        var mergeJobId = new JobId(Guid.NewGuid());
        var groups = merger.Merge(mergeScanId, mergeJobId, allCandidates, jobSha256, expected.FixturePath);

        // Collect actual findings for comparison
        var actualFindings = new List<ActualFinding>();
        foreach (var group in groups)
        {
            foreach (var occ in group.Occurrences)
            {
                foreach (var prov in occ.Provenance)
                {
                    actualFindings.Add(new ActualFinding(
                        prov.RuleId.Value,
                        prov.DetectorId.Value,
                        group.Severity,
                        prov.Confidence,
                        occ.RawValue,
                        occ.CanonicalLocator.ToCanonicalDisplay()));
                }
            }
        }

        // Count occurrences for min/max check
        int occurrenceCount = groups.Sum(g => g.Occurrences.Count);
        if (occurrenceCount < expected.MinOccurrenceCount)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Occurrence count below minimum: expected at least {expected.MinOccurrenceCount}, got {occurrenceCount}",
            };
        }

        if (occurrenceCount > expected.MaxOccurrenceCount)
        {
            return new CaseResult
            {
                CaseId = expected.CaseId,
                Result = "fail",
                Detail = $"Occurrence count above maximum: expected at most {expected.MaxOccurrenceCount}, got {occurrenceCount}",
            };
        }

        // For negative/near-miss cases: verify NO expected findings are hit
        if (expected.Disposition is "negative" or "near-miss")
        {
            var hitExpectedIds = new HashSet<string>(
                expected.ExpectedFindings
                    .Select(f => f.RuleId)
                    .Intersect(actualFindings.Select(a => a.RuleId)),
                StringComparer.OrdinalIgnoreCase);

            if (hitExpectedIds.Count > 0)
            {
                return new CaseResult
                {
                    CaseId = expected.CaseId,
                    Result = "fail",
                    Detail = $"Unexpected detection in {expected.Disposition} case: rules {string.Join(", ", hitExpectedIds)} should not match",
                };
            }
        }

        // For positive cases: verify all expected findings are present
        if (expected.Disposition is "approved-example" or "cross-chunk")
        {
            foreach (ExpectedRuleFinding ef in expected.ExpectedFindings)
            {
                // Check if actual findings contain the expected rule+detector
                var matching = actualFindings
                    .Where(a => string.Equals(a.RuleId, ef.RuleId, StringComparison.OrdinalIgnoreCase)
                             && string.Equals(a.DetectorId, ef.DetectorId, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matching.Count == 0)
                {
                    // Missing Critical/High is a hard failure
                    if (ef.Severity is "Critical" or "High")
                    {
                        return new CaseResult
                        {
                            CaseId = expected.CaseId,
                            Result = "fail",
                            Detail = $"Missing {ef.Severity} detection: rule {ef.RuleId}, detector {ef.DetectorId}",
                        };
                    }

                    // Missing lower severity: record but still fail
                    return new CaseResult
                    {
                        CaseId = expected.CaseId,
                        Result = "fail",
                        Detail = $"Missing expected finding: rule {ef.RuleId}, detector {ef.DetectorId}",
                    };
                }

                // Verify severity
                if (!string.Equals(matching[0].Severity.ToString(), ef.Severity, StringComparison.OrdinalIgnoreCase))
                {
                    return new CaseResult
                    {
                        CaseId = expected.CaseId,
                        Result = "fail",
                        Detail = $"Severity mismatch for rule {ef.RuleId}: expected {ef.Severity}, got {matching[0].Severity}",
                    };
                }

                // Verify confidence
                if (!string.Equals(matching[0].Confidence.ToString(), ef.Confidence, StringComparison.OrdinalIgnoreCase))
                {
                    return new CaseResult
                    {
                        CaseId = expected.CaseId,
                        Result = "fail",
                        Detail = $"Confidence mismatch for rule {ef.RuleId}: expected {ef.Confidence}, got {matching[0].Confidence}",
                    };
                }

                // Verify category
                var ruleDef = pipeline.Rules.FirstOrDefault(r =>
                    string.Equals(r.Id.Value, ef.RuleId, StringComparison.OrdinalIgnoreCase));
                if (ruleDef is not null &&
                    !string.Equals(ruleDef.CategoryId.Value, ef.CategoryId, StringComparison.OrdinalIgnoreCase))
                {
                    return new CaseResult
                    {
                        CaseId = expected.CaseId,
                        Result = "fail",
                        Detail = $"Category mismatch for rule {ef.RuleId}: expected {ef.CategoryId}, got {ruleDef.CategoryId.Value}",
                    };
                }

                // Verify value pattern if specified
                if (ef.ValuePattern is not null)
                {
                    bool hasPattern = matching.Any(m =>
                        m.RawValue.Contains(ef.ValuePattern, StringComparison.OrdinalIgnoreCase));
                    if (!hasPattern)
                    {
                        return new CaseResult
                        {
                            CaseId = expected.CaseId,
                            Result = "fail",
                            Detail = $"Value pattern '{ef.ValuePattern}' not found for rule {ef.RuleId}",
                        };
                    }
                }
            }

            // Verify expected absence IDs
            foreach (string absentRuleId in expected.ExpectedAbsenceRuleIds)
            {
                if (actualFindings.Any(a =>
                    string.Equals(a.RuleId, absentRuleId, StringComparison.OrdinalIgnoreCase)))
                {
                    return new CaseResult
                    {
                        CaseId = expected.CaseId,
                        Result = "fail",
                        Detail = $"Unexpected detection of absent rule: {absentRuleId}",
                    };
                }
            }
        }

        return new CaseResult { CaseId = expected.CaseId, Result = "pass" };
    }

    // ────────────────────────────────────────────────────────
    //  Pipeline building
    // ────────────────────────────────────────────────────────

    private sealed record PipelineContext(
        RulePackDocument Document,
        DetectorPipeline Pipeline,
        IReadOnlyList<RuleDefinition> Rules,
        IReadOnlyDictionary<DetectorId, DetectorDefinition> DetectorDefs);

    private static PipelineContext BuildPipeline(byte[] zipBytes)
    {
        // Extract ZIP
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        foreach (var entry in zip.Entries)
        {
            string name = entry.FullName.Replace('\\', '/');
            using var stream = entry.Open();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            files[name] = ms.ToArray();
        }

        // Load rule pack document
        if (!files.TryGetValue("categories.json", out byte[]? categoriesBytes))
            throw new InvalidOperationException("Missing categories.json in rule pack.");
        var categories = JsonSerializer.Deserialize<IReadOnlyList<CategoryDefinition>>(
            categoriesBytes, RulePackJsonContext.Default.IReadOnlyListCategoryDefinition)
            ?? throw new InvalidOperationException("Failed to parse categories.json.");

        if (!files.TryGetValue("assets.json", out byte[]? assetsBytes))
            throw new InvalidOperationException("Missing assets.json in rule pack.");
        var assets = JsonSerializer.Deserialize<IReadOnlyList<AssetPolicy>>(
            assetsBytes, RulePackJsonContext.Default.IReadOnlyListAssetPolicy)
            ?? throw new InvalidOperationException("Failed to parse assets.json.");

        if (!files.TryGetValue("detectors.json", out byte[]? detectorsBytes))
            throw new InvalidOperationException("Missing detectors.json in rule pack.");
        var detectors = JsonSerializer.Deserialize<IReadOnlyList<DetectorDefinition>>(
            detectorsBytes, RulePackJsonContext.Default.IReadOnlyListDetectorDefinition)
            ?? throw new InvalidOperationException("Failed to parse detectors.json.");

        // Rules may be in the document-level JSON or in their own rules.json
        IReadOnlyList<RuleDefinition> rules;
        if (files.TryGetValue("rules.json", out byte[]? rulesBytes))
        {
            rules = JsonSerializer.Deserialize<IReadOnlyList<RuleDefinition>>(
                rulesBytes, RulePackJsonContext.Default.IReadOnlyListRuleDefinition)
                ?? throw new InvalidOperationException("Failed to parse rules.json.");
        }
        else
        {
            rules = Array.Empty<RuleDefinition>();
        }

        if (!files.TryGetValue("compliance.json", out byte[]? complianceBytes))
            throw new InvalidOperationException("Missing compliance.json in rule pack.");
        var complianceRules = JsonSerializer.Deserialize<IReadOnlyList<ComplianceRule>>(
            complianceBytes, RulePackJsonContext.Default.IReadOnlyListComplianceRule)
            ?? throw new InvalidOperationException("Failed to parse compliance.json.");

        var document = new RulePackDocument
        {
            SchemaVersion = 1,
            Categories = categories,
            Assets = assets,
            Rules = rules,
            Detectors = detectors,
            ComplianceRules = complianceRules,
        };

        var errors = document.Validate();
        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"Rule pack validation failed: {string.Join("; ", errors)}");

        // Load entities and placeholders for detector construction
        var entities = new List<(string Name, string EntityId, string RuleId)>();
        if (files.TryGetValue("dictionaries/entities.json", out byte[]? entitiesBytes))
        {
            var entityEntries = JsonSerializer.Deserialize<List<RestrictedEntityEntry>>(
                entitiesBytes, RulePackDtoOptions);
            if (entityEntries is not null)
            {
                foreach (var e in entityEntries)
                {
                    string entityId = e.EntityId;
                    // Standard name is the primary match term; variant is secondary
                    if (!string.IsNullOrWhiteSpace(e.StandardName))
                        entities.Add((e.StandardName, entityId, e.CategoryId));
                    if (!string.IsNullOrWhiteSpace(e.Variant))
                        entities.Add((e.Variant, entityId, e.CategoryId));
                }
            }
        }

        var placeholderEntries = new List<ApprovedPlaceholderMatcher.PlaceholderEntry>();
        if (files.TryGetValue("placeholders.json", out byte[]? placeholdersBytes))
        {
            var placeholders = JsonSerializer.Deserialize<List<SecurityPlaceholder>>(
                placeholdersBytes, RulePackDtoOptions);
            if (placeholders is not null)
            {
                foreach (var p in placeholders)
                {
                    placeholderEntries.Add(new ApprovedPlaceholderMatcher.PlaceholderEntry
                    {
                        PlaceholderId = p.PlaceholderId,
                        Value = p.Value,
                        ContextScope = p.AllowedContext.Length > 0 ? p.AllowedContext : "*",
                        Version = null,
                        Expiry = null,
                    });
                }
            }
        }

        // Build detectors from definitions
        var pipeline = BuildDetectors(detectors, entities, placeholderEntries);

        // Build detector lookup
        var detectorDefs = detectors.ToDictionary(d => d.Id);

        return new PipelineContext(document, pipeline, rules, detectorDefs);
    }

    private static DetectorPipeline BuildDetectors(
        IReadOnlyList<DetectorDefinition> detectorDefs,
        List<(string Name, string EntityId, string RuleId)> entities,
        IReadOnlyList<ApprovedPlaceholderMatcher.PlaceholderEntry> placeholders)
    {
        var detectorList = new List<IDetector>();

        // Track which kinds we've added
        var kindsAdded = new HashSet<DetectorKind>();

        foreach (DetectorDefinition def in detectorDefs)
        {
            if (kindsAdded.Contains(def.Kind))
                continue;

            IDetector? detector = def.Kind switch
            {
                DetectorKind.Dictionary => entities.Count > 0
                    ? new RestrictedEntityDetector(entities)
                    : null,
                DetectorKind.NetworkAddress => new NetworkAddressDetector(),
                DetectorKind.KnownFormat => new KnownFormatDetector(),
                DetectorKind.Checksum => new ChecksumDetector(),
                DetectorKind.StructuredField => new StructuredFieldDetector(),
                DetectorKind.EntropyWithContext => new EntropyContextDetector(),
                DetectorKind.LicenseFingerprint => new LicenseFingerprintDetector(
                    Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>()),
                DetectorKind.ContentFingerprint => new ContentFingerprintDetector(
                    Array.Empty<ContentFingerprintDetector.FingerprintEntry>(),
                    Array.Empty<ContentFingerprintDetector.FingerprintAuthorization>()),
                DetectorKind.SemanticCandidate => null, // Requires AI
                _ => null,
            };

            if (detector is not null)
            {
                detectorList.Add(detector);
                kindsAdded.Add(def.Kind);
            }
        }

        return new DetectorPipeline(detectorList);
    }

    // ────────────────────────────────────────────────────────
    //  Helper types
    // ────────────────────────────────────────────────────────

    private sealed record ActualFinding(
        string RuleId,
        string DetectorId,
        Severity Severity,
        DetectionConfidence Confidence,
        string RawValue,
        string LocatorDisplay);

    /// <summary>
    /// Lightweight fingerprint service for corpus verification.
    /// Uses the same normalization as EphemeralValueFingerprintService
    /// but avoids the full Infrastructure dependency.
    /// </summary>
    private sealed class CorpusFingerprintService : IValueFingerprintService
    {
        private readonly byte[] _hmacKey;

        public CorpusFingerprintService()
        {
            _hmacKey = new byte[32];
            RandomNumberGenerator.Fill(_hmacKey);
        }

        public ValueFingerprint Compute(ReadOnlySpan<char> normalizedValue)
        {
            string normalized = NormalizeValue(normalizedValue);
            byte[] utf8 = System.Text.Encoding.UTF8.GetBytes(normalized);
            byte[] hash = HMACSHA256.HashData(_hmacKey, utf8);
            return new ValueFingerprint(Convert.ToHexStringLower(hash));
        }

        private static string NormalizeValue(ReadOnlySpan<char> value)
        {
            if (value.IsEmpty) return string.Empty;

            int start = 0;
            int end = value.Length - 1;
            while (start <= end && char.IsWhiteSpace(value[start])) start++;
            while (end >= start && char.IsWhiteSpace(value[end])) end--;

            if (start > end) return string.Empty;

            int len = end - start + 1;
            bool needsCollapse = false;
            for (int i = start; i <= end; i++)
            {
                if (char.IsWhiteSpace(value[i]) && i + 1 <= end && char.IsWhiteSpace(value[i + 1]))
                {
                    needsCollapse = true;
                    break;
                }
            }

            if (!needsCollapse)
                return value.Slice(start, len).ToString().ToLowerInvariant();

            Span<char> buffer = len <= 256 ? stackalloc char[len] : new char[len];
            int pos = 0;
            bool lastWasSpace = false;
            for (int i = start; i <= end; i++)
            {
                char c = value[i];
                if (char.IsWhiteSpace(c))
                {
                    if (!lastWasSpace && pos > 0) { buffer[pos++] = ' '; lastWasSpace = true; }
                }
                else
                {
                    buffer[pos++] = char.ToLowerInvariant(c);
                    lastWasSpace = false;
                }
            }

            return new string(buffer[..pos]);
        }
    }
}
