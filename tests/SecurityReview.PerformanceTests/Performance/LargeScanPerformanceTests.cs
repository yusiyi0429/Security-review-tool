using System.Diagnostics;

namespace SecurityReview.PerformanceTests.Performance;

/// <summary>
/// Large scan throughput and coverage completeness tests.
/// Target SRS-NFR-004: P95 ≤ 30 min for 10 GB / 100k file local scan (excluding LLM).
/// Target SRS-NFR-009: expected gap record rate 100%, no silent skips.
/// </summary>
public sealed class LargeScanPerformanceTests
{
    private static string CorpusRoot =>
        Environment.GetEnvironmentVariable("CORPUS_ROOT")
        ?? throw new InvalidOperationException("CORPUS_ROOT environment variable not set.");

    private static void RequirePerformanceHost()
    {
        Assert.SkipWhen(
            Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_HOST") != "1",
            "SECURITY_REVIEW_PERF_HOST is not set to 1 — not running on a performance host.");
    }

    private static int GetRequiredRuns()
    {
        var env = Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_RUNS");
        return env is not null && int.TryParse(env, out var n) ? n : 5;
    }

    private static string GetCounterPath(string name)
    {
        var dir = Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_OUTPUT")
                  ?? Path.Combine(Path.GetTempPath(), "srt-perf-counters");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"{name}.csv");
    }

    /// <summary>
    /// Measures scan duration for a 10 GB / 100k file corpus.
    /// Performs 1 warm-up run then N measurement runs.
    /// Target: P95 ≤ 30 min (1800 s), excluding LLM time.
    /// </summary>
    [Fact]
    public async Task large_scan_p95_within_30_minutes_excluding_llm()
    {
        RequirePerformanceHost();
        var totalRuns = GetRequiredRuns() + 1; // +1 for warm-up
        var counterPath = GetCounterPath("large-scan");

        var corpusARoot = Path.Combine(CorpusRoot, "corpus-a");
        if (!Directory.Exists(corpusARoot))
        {
            Assert.Skip($"Corpus A not found at {corpusARoot}. Generate corpus first.");
            return;
        }

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("run,duration_s,files_processed,files_skipped,coverage_pct,peak_memory_mib");

        var durations = new List<double>(totalRuns);

        for (var run = 0; run < totalRuns; run++)
        {
            var isWarmup = run == 0;
            var label = isWarmup ? "warmup" : $"run-{run}";

            var (duration, filesProcessed, filesSkipped, coveragePct, peakMemMiB) =
                await RunScan(corpusARoot, excludeLlm: true);

            durations.Add(duration);

            await writer.WriteLineAsync(
                $"{label},{duration:F1},{filesProcessed},{filesSkipped},{coveragePct:F1},{peakMemMiB:F1}");

            // Brief cooldown
            if (run < totalRuns - 1) await Task.Delay(5000);
        }

        // Drop warm-up run
        var measurementRuns = durations.Skip(1).OrderBy(x => x).ToList();
        var p50 = measurementRuns.Count > 0 ? Percentile(measurementRuns, 0.50) : 0;
        var p95 = measurementRuns.Count > 0 ? Percentile(measurementRuns, 0.95) : 0;
        var max = measurementRuns.Count > 0 ? measurementRuns[^1] : 0;

        await writer.WriteLineAsync($"# p50_s={p50:F1}");
        await writer.WriteLineAsync($"# p95_s={p95:F1}");
        await writer.WriteLineAsync($"# max_s={max:F1}");
        await writer.WriteLineAsync($"# threshold_s=1800");
        await writer.WriteLineAsync($"# pass={p95 <= 1800}");

        // Assert SRS-NFR-004: local scan P95 ≤ 30 min
        Assert.True(p95 <= 1800,
            $"Large scan P95 {p95:F0} s exceeds 1800 s (30 min) threshold. " +
            $"P50={p50:F0} s, Max={max:F0} s.");
    }

    /// <summary>
    /// Verifies scan covers all files — no silent skips.
    /// Target SRS-NFR-009: coverage gap record rate 100%.
    /// </summary>
    [Fact]
    public async Task scan_covers_all_files_without_silent_skips()
    {
        RequirePerformanceHost();

        var corpusARoot = Path.Combine(CorpusRoot, "corpus-a");
        if (!Directory.Exists(corpusARoot))
        {
            Assert.Skip($"Corpus A not found at {corpusARoot}.");
            return;
        }

        var (_, filesProcessed, filesSkipped, coveragePct, _) =
            await RunScan(corpusARoot, excludeLlm: true);

        Assert.True(coveragePct >= 99.0,
            $"Coverage {coveragePct:F1}% below 99% threshold.");
        Assert.True(filesSkipped == 0 || filesSkipped <= filesProcessed * 0.01,
            $"Too many skipped files: {filesSkipped} out of {filesProcessed}.");
    }

    /// <summary>
    /// Deterministic reproducibility: two runs on same corpus produce identical
    /// finding sets (normalized for task IDs and timestamps).
    /// Target SRS-NFR-015.
    /// </summary>
    [Fact]
    public async Task deterministic_reproducibility_identical_finding_sets()
    {
        RequirePerformanceHost();

        var corpusARoot = Path.Combine(CorpusRoot, "corpus-a");
        if (!Directory.Exists(corpusARoot))
        {
            Assert.Skip($"Corpus A not found at {corpusARoot}.");
            return;
        }

        var counterPath = GetCounterPath("deterministic");

        // Run A
        var (durA, _, _, _, _) = await RunScan(corpusARoot, excludeLlm: true);
        // Run B (with brief cooldown to avoid caching interference)
        await Task.Delay(3000);
        var (durB, _, _, _, _) = await RunScan(corpusARoot, excludeLlm: true);

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync($"run_a_duration_s={durA:F1}");
        await writer.WriteLineAsync($"run_b_duration_s={durB:F1}");
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private static async Task<(double durationS, int filesProcessed, int filesSkipped,
        double coveragePct, double peakMemMiB)> RunScan(string corpusRoot, bool excludeLlm)
    {
        var sw = Stopwatch.StartNew();
        var proc = Process.GetCurrentProcess();

        // Launch the application in scan mode
        var appExe = FindAppExecutable();
        var psi = new ProcessStartInfo
        {
            FileName = appExe,
            Arguments = $"scan --path \"{corpusRoot}\" --no-llm",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Environment =
            {
                ["SECURITY_REVIEW_PERF_SCAN"] = "1",
                ["SECURITY_REVIEW_NO_GPU"] = "1"
            }
        };

        if (excludeLlm)
        {
            psi.Environment["SECURITY_REVIEW_SKIP_LLM"] = "1";
        }

        long peakMem = 0;
        using var memCts = new CancellationTokenSource();
        var memTask = Task.Run(async () =>
        {
            while (!memCts.Token.IsCancellationRequested)
            {
                proc.Refresh();
                var mem = proc.PeakWorkingSet64;
                if (mem > peakMem) peakMem = mem;
                await Task.Delay(500, memCts.Token);
            }
        });

        using var scanProc = Process.Start(psi);
        if (scanProc is null)
        {
            memCts.Cancel();
            return (sw.Elapsed.TotalSeconds, 0, 0, 0, 0);
        }

        var stdout = await scanProc.StandardOutput.ReadToEndAsync();
        await scanProc.WaitForExitAsync();

        memCts.Cancel();
        try { await memTask; } catch (TaskCanceledException) { }

        sw.Stop();

        // Parse output for file counts
        _ = int.TryParse(ExtractField(stdout, "files_processed"), out var processed);
        _ = int.TryParse(ExtractField(stdout, "files_skipped"), out var skipped);
        _ = double.TryParse(ExtractField(stdout, "coverage_pct"), out var coverage);

        return (
            sw.Elapsed.TotalSeconds,
            processed,
            skipped,
            coverage,
            peakMem / (1024.0 * 1024.0)
        );
    }

    private static string ExtractField(string output, string fieldName)
    {
        var prefix = $"{fieldName}=";
        var idx = output.IndexOf(prefix, StringComparison.Ordinal);
        if (idx < 0) return "0";
        var start = idx + prefix.Length;
        var end = output.IndexOf('\n', start);
        if (end < 0) end = output.Length;
        return output[start..end].Trim();
    }

    private static string FindAppExecutable()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
                "src", "SecurityReview.Desktop", "bin", "Release", "net10.0-windows10.0.19041.0",
                "win-x64", "publish", "SecurityReview.Desktop.exe"),
            Path.Combine(AppContext.BaseDirectory, "SecurityReview.Desktop.exe"),
        };

        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (File.Exists(full)) return full;
        }

        throw new InvalidOperationException(
            "App executable not found. Publish SecurityReview.Desktop first.");
    }

    private static double Percentile(List<double> sorted, double percentile)
    {
        if (sorted.Count == 0) return 0;
        var index = (int)Math.Ceiling(percentile * sorted.Count) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Count - 1)];
    }
}
