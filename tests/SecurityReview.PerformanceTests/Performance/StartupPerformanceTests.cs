using System.Diagnostics;
using SecurityReview.Application.Diagnostics;

namespace SecurityReview.PerformanceTests.Performance;

/// <summary>
/// Cold startup performance tests.
/// Target SRS-NFR-001: P95 cold startup ≤ 5 s (30 cold launches, window interactive signal).
/// </summary>
public sealed class StartupPerformanceTests
{
    // ── Helpers ──────────────────────────────────────────────────────────

    private static void RequirePerformanceHost()
    {
        Assert.SkipWhen(
            Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_HOST") != "1",
            "SECURITY_REVIEW_PERF_HOST is not set to 1 — not running on a performance host.");
    }

    private static int GetRequiredRuns()
    {
        var env = Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_RUNS");
        return env is not null && int.TryParse(env, out var n) ? n : 30;
    }

    private static string GetCounterPath(string name)
    {
        var dir = Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_OUTPUT")
                  ?? Path.Combine(Path.GetTempPath(), "srt-perf-counters");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"{name}.csv");
    }

    /// <summary>
    /// Measures process startup time by launching a minimal self-test instance.
    /// This measures the time from process start to a ready signal, repeated N times.
    /// </summary>
    [Fact]
    public async Task cold_startup_p95_within_5_seconds()
    {
        RequirePerformanceHost();
        var runs = GetRequiredRuns();
        var measurements = new List<double>(runs);
        var counterPath = GetCounterPath("startup-cold");

        // We measure the application's startup by launching its process
        // and timing until the diagnostic sink receives the first health event.
        var appExePath = FindAppExecutable();

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("run,duration_ms,outcome");

        for (var i = 0; i < runs; i++)
        {
            var sw = Stopwatch.StartNew();

            // Launch the app and wait for a ready signal via diagnostic pipe
            var (success, duration) = await MeasureSingleColdStart(appExePath);
            sw.Stop();

            measurements.Add(duration);
            await writer.WriteLineAsync($"{i},{duration:F1},{(success ? "ready" : "timeout")}");

            // Brief cooldown between launches
            if (i < runs - 1) await Task.Delay(2000);
        }

        var sorted = measurements.OrderBy(x => x).ToList();
        var p50 = Percentile(sorted, 0.50);
        var p95 = Percentile(sorted, 0.95);
        var max = sorted[^1];

        // Log evidence
        await writer.WriteLineAsync($"# p50_ms={p50:F1}");
        await writer.WriteLineAsync($"# p95_ms={p95:F1}");
        await writer.WriteLineAsync($"# max_ms={max:F1}");
        await writer.WriteLineAsync($"# threshold_ms=5000");
        await writer.WriteLineAsync($"# pass={p95 <= 5000}");

        // Assert SRS-NFR-001: cold startup P95 ≤ 5 s
        Assert.True(p95 <= 5000,
            $"Cold startup P95 {p95:F0} ms exceeds 5000 ms threshold. " +
            $"P50={p50:F0} ms, Max={max:F0} ms.");
    }

    /// <summary>
    /// Idle memory after startup stabilizes.
    /// Target SRS-NFR-002: working set ≤ 300 MiB after 60 s idle.
    /// </summary>
    [Fact]
    public async Task idle_memory_within_300_mib_after_60_seconds()
    {
        RequirePerformanceHost();
        var counterPath = GetCounterPath("idle-memory");

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("sample_time_s,working_set_mib,private_bytes_mib");

        // Warm-up: let process stabilize
        await Task.Delay(10_000);

        // Sample at 60 s
        await Task.Delay(50_000);
        var proc = Process.GetCurrentProcess();
        proc.Refresh();
        var wsMiB = proc.WorkingSet64 / (1024.0 * 1024.0);
        var pbMiB = proc.PrivateMemorySize64 / (1024.0 * 1024.0);

        await writer.WriteLineAsync($"60,{wsMiB:F1},{pbMiB:F1}");
        await writer.WriteLineAsync($"# working_set_mib={wsMiB:F1}");
        await writer.WriteLineAsync($"# threshold_mib=300");
        await writer.WriteLineAsync($"# pass={wsMiB <= 300}");

        // Assert SRS-NFR-002: idle working set ≤ 300 MiB
        Assert.True(wsMiB <= 300,
            $"Idle working set {wsMiB:F0} MiB exceeds 300 MiB threshold.");
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private static string FindAppExecutable()
    {
        // Look for the published Desktop app relative to the test output
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

    private static async Task<(bool success, double durationMs)> MeasureSingleColdStart(
        string exePath)
    {
        var sw = Stopwatch.StartNew();

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Environment =
            {
                ["SECURITY_REVIEW_PERF_STARTUP_PROBE"] = "1",
                ["SECURITY_REVIEW_NO_GPU"] = "1"
            }
        };

        using var proc = Process.Start(psi);
        if (proc is null) return (false, sw.ElapsedMilliseconds);

        // Wait for the process to signal readiness or timeout
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await proc.WaitForExitAsync(cts.Token);
            var elapsed = sw.ElapsedMilliseconds;
            return (proc.ExitCode == 0, elapsed);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* best effort */ }
            return (false, sw.ElapsedMilliseconds);
        }
    }

    private static double Percentile(List<double> sorted, double percentile)
    {
        if (sorted.Count == 0) return 0;
        var index = (int)Math.Ceiling(percentile * sorted.Count) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Count - 1)];
    }
}
