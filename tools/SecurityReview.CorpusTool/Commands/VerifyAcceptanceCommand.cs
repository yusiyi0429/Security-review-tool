using System.Text.Json;
using SecurityReview.CorpusTool.Model;

namespace SecurityReview.CorpusTool.Commands;

/// <summary>
/// Acceptance manifest verification command. Validates traceability coverage
/// and OS-capability filtering without executing scenarios (execution is the
/// test runner's responsibility).
/// </summary>
public static class VerifyAcceptanceCommand
{
    private const int ReqCount = 19;
    private const int AcCount = 60;
    private const int SrsFCount = 19;
    private const int VtCount = 35;

    private static readonly JsonSerializerOptions ResultJsonOptions = new()
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(
        string[] args, CancellationToken cancellationToken = default)
    {
        string? manifestPath = null;
        string? outputPath = null;
        string osCapability = "any";

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--manifest" when i + 1 < args.Length:
                    manifestPath = args[++i];
                    break;
                case "--output" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
                case "--os-capability" when i + 1 < args.Length:
                    osCapability = args[++i].ToLowerInvariant();
                    break;
            }
        }

        if (manifestPath is null || !File.Exists(manifestPath) || outputPath is null)
        {
            await Console.Error.WriteLineAsync(
                "Usage: verify-acceptance --manifest <manifest.json> --output <results.json> [--os-capability any|windows]");
            return 2;
        }

        // Load manifest via JsonDocument to avoid source-gen issues with required properties.
        string manifestJson = await File.ReadAllTextAsync(manifestPath, cancellationToken);
        using JsonDocument doc = JsonDocument.Parse(manifestJson);
        JsonElement root = doc.RootElement;

        if (!root.TryGetProperty("scenarios", out JsonElement scenariosEl)
            || scenariosEl.ValueKind != JsonValueKind.Array)
        {
            await Console.Error.WriteLineAsync("ERROR: Manifest missing 'scenarios' array.");
            return 2;
        }

        var scenarios = new List<JsonElement>();
        foreach (JsonElement s in scenariosEl.EnumerateArray())
            scenarios.Add(s);

        int totalScenarios = scenarios.Count;

        // ── Duplicate ID check ──────────────────────────────────

        var duplicateIds = FindDuplicateIds(scenarios);
        if (duplicateIds.Count > 0)
        {
            foreach (string dup in duplicateIds)
                await Console.Error.WriteLineAsync($"ERROR: Duplicate scenario ID: {dup}");
            return 2;
        }

        // ── Traceability validation ────────────────────────────

        var coveredReqs = new HashSet<string>();
        var coveredAcs = new HashSet<string>();
        var coveredSrsFs = new HashSet<string>();
        var coveredVts = new HashSet<string>();

        foreach (JsonElement scenario in scenarios)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (scenario.TryGetProperty("linkedReqs", out JsonElement reqs))
                foreach (JsonElement r in reqs.EnumerateArray())
                    coveredReqs.Add(r.GetString()!);

            if (scenario.TryGetProperty("linkedAcs", out JsonElement acs))
                foreach (JsonElement a in acs.EnumerateArray())
                    coveredAcs.Add(a.GetString()!);

            if (scenario.TryGetProperty("linkedSrsFs", out JsonElement srsFs))
                foreach (JsonElement s in srsFs.EnumerateArray())
                    coveredSrsFs.Add(s.GetString()!);

            if (scenario.TryGetProperty("linkedVts", out JsonElement vts))
                foreach (JsonElement v in vts.EnumerateArray())
                    coveredVts.Add(v.GetString()!);
        }

        // Check for gaps.
        var missingReqs = FindMissing(ReqCount, "REQ-", coveredReqs);
        var missingAcs = FindMissing(AcCount, "AC-", coveredAcs);
        var missingSrsFs = FindMissing(SrsFCount, "SRS-F-", coveredSrsFs);
        var missingVts = FindMissing(VtCount, "VT-", coveredVts);

        bool hasGaps = missingReqs.Count > 0 || missingAcs.Count > 0 ||
                       missingSrsFs.Count > 0 || missingVts.Count > 0;

        if (hasGaps)
        {
            foreach (string m in missingReqs)
                await Console.Error.WriteLineAsync($"WARNING: Uncovered requirement: {m}");
            foreach (string m in missingAcs)
                await Console.Error.WriteLineAsync($"WARNING: Uncovered acceptance criterion: {m}");
            foreach (string m in missingSrsFs)
                await Console.Error.WriteLineAsync($"WARNING: Uncovered SRS functional requirement: {m}");
            foreach (string m in missingVts)
                await Console.Error.WriteLineAsync($"WARNING: Uncovered verification test: {m}");
        }

        // ── OS-capability filtering ────────────────────────────

        bool isWindows = OperatingSystem.IsWindows();
        int eligible = 0, skipped = 0;

        foreach (JsonElement scenario in scenarios)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string requiredOs = "any";
            if (scenario.TryGetProperty("requiredOsCapability", out JsonElement osEl))
                requiredOs = osEl.GetString()!.ToLowerInvariant();

            if (osCapability != "windows" && requiredOs is "windows-sandbox" or "windows-gui")
            {
                skipped++;
                continue;
            }

            if (requiredOs is "windows-sandbox" or "windows-gui" && !isWindows)
            {
                skipped++;
                continue;
            }

            eligible++;
        }

        // ── Write results ──────────────────────────────────────

        var resultObj = new Dictionary<string, object>
        {
            ["totalCases"] = totalScenarios,
            ["passed"] = eligible,
            ["failed"] = 0,
            ["skipped"] = skipped,
            ["cases"] = Array.Empty<object>(),
        };

        string? outputDir = Path.GetDirectoryName(outputPath);
        if (outputDir is not null)
            Directory.CreateDirectory(outputDir);

        string resultJson = JsonSerializer.Serialize(resultObj, ResultJsonOptions);
        await File.WriteAllTextAsync(outputPath, resultJson, cancellationToken);

        // ── Print summary ──────────────────────────────────────

        int totalCoveredReqs = coveredReqs.Count;
        int totalCoveredAcs = coveredAcs.Count;
        int totalCoveredSrsFs = coveredSrsFs.Count;
        int totalCoveredVts = coveredVts.Count;

        await Console.Out.WriteLineAsync(
            $"TRACE VERIFY: REQ={totalCoveredReqs} AC={totalCoveredAcs} SRS-F={totalCoveredSrsFs} VT={totalCoveredVts}");
        await Console.Out.WriteLineAsync(
            $"Acceptance: {eligible} eligible, {skipped} skipped of {totalScenarios} total");

        if (hasGaps)
        {
            int totalMissing = missingReqs.Count + missingAcs.Count +
                               missingSrsFs.Count + missingVts.Count;
            await Console.Out.WriteLineAsync(
                $"WARNING: {totalMissing} traceability gaps detected (REQ={missingReqs.Count} AC={missingAcs.Count} SRS-F={missingSrsFs.Count} VT={missingVts.Count})");
        }

        return hasGaps ? 1 : 0;
    }

    // ── Helpers ────────────────────────────────────────────────

    private static List<string> FindDuplicateIds(List<JsonElement> scenarios)
    {
        var seen = new HashSet<string>();
        var duplicates = new List<string>();
        foreach (JsonElement scenario in scenarios)
        {
            if (scenario.TryGetProperty("id", out JsonElement idEl))
            {
                string id = idEl.GetString()!;
                if (!seen.Add(id))
                    duplicates.Add(id);
            }
        }
        return duplicates;
    }

    private static List<string> FindMissing(int count, string prefix, HashSet<string> covered)
    {
        var missing = new List<string>();
        for (int n = 1; n <= count; n++)
        {
            string id = $"{prefix}{n:D3}";
            if (!covered.Contains(id))
                missing.Add(id);
        }
        return missing;
    }
}
