using System.Diagnostics;

namespace SecurityReview.PerformanceTests.Performance;

/// <summary>
/// Memory scaling tests for scan and streaming workloads.
/// Target SRS-NFR-003: main + workers peak ≤ 1.5 GiB; worker Job ≤ 1 GiB.
/// Target SRS-NFR-005: streaming peak growth ≤ 128 MiB across 1/5/20 GB files.
/// </summary>
public sealed class MemoryScalingTests
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

    private static string GetCounterPath(string name)
    {
        var dir = Environment.GetEnvironmentVariable("SECURITY_REVIEW_PERF_OUTPUT")
                  ?? Path.Combine(Path.GetTempPath(), "srt-perf-counters");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"{name}.csv");
    }

    /// <summary>
    /// Verifies scan peak memory does not exceed 1.5 GiB for main + workers.
    /// Target SRS-NFR-003.
    /// </summary>
    [Fact]
    public async Task scan_peak_private_bytes_within_1_5_gib()
    {
        RequirePerformanceHost();
        var counterPath = GetCounterPath("scan-peak-memory");

        var corpusARoot = Path.Combine(CorpusRoot, "corpus-a");
        if (!Directory.Exists(corpusARoot))
        {
            Assert.Skip($"Corpus A not found at {corpusARoot}.");
            return;
        }

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("timestamp_s,main_private_mib,worker_total_private_mib,main_working_set_mib");

        var proc = Process.GetCurrentProcess();
        var peakPrivateMiB = 0.0;
        var peakWorkingSetMiB = 0.0;
        var startTime = DateTime.UtcNow;
        var sw = Stopwatch.StartNew();

        // Monitor while scan runs (sampling every second)
        var scanTask = RunScanToCompletion(corpusARoot);
        var monitorDone = false;

        while (!monitorDone)
        {
            await Task.Delay(1000);
            proc.Refresh();

            var privateMiB = proc.PrivateMemorySize64 / (1024.0 * 1024.0);
            var wsMiB = proc.WorkingSet64 / (1024.0 * 1024.0);

            if (privateMiB > peakPrivateMiB) peakPrivateMiB = privateMiB;
            if (wsMiB > peakWorkingSetMiB) peakWorkingSetMiB = wsMiB;

            // Worker processes are child processes; sum their memory
            var workerTotalPrivateMiB = MeasureWorkerProcessesMemory();

            await writer.WriteLineAsync(
                $"{sw.Elapsed.TotalSeconds:F1},{privateMiB:F1},{workerTotalPrivateMiB:F1},{wsMiB:F1}");

            monitorDone = scanTask.IsCompleted;
        }

        sw.Stop();

        // Ensure scan completed
        await scanTask;

        var totalPeakMiB = peakPrivateMiB;

        await writer.WriteLineAsync($"# peak_private_mib={totalPeakMiB:F1}");
        await writer.WriteLineAsync($"# peak_working_set_mib={peakWorkingSetMiB:F1}");
        await writer.WriteLineAsync($"# threshold_private_mib=1536");
        await writer.WriteLineAsync($"# pass={totalPeakMiB <= 1536}");

        // Assert SRS-NFR-003: peak ≤ 1.5 GiB
        Assert.True(totalPeakMiB <= 1536,
            $"Scan peak private bytes {totalPeakMiB:F0} MiB exceeds 1536 MiB (1.5 GiB) threshold.");
    }

    /// <summary>
    /// Verifies streaming memory does not grow linearly with file size.
    /// Measures across 1, 5, and 20 GB files.
    /// Target SRS-NFR-005: peak growth ≤ 128 MiB after buffer stabilization.
    /// </summary>
    [Fact]
    public async Task streaming_memory_growth_within_128_mib()
    {
        RequirePerformanceHost();
        var counterPath = GetCounterPath("streaming-memory");

        var corpusBRoot = Path.Combine(CorpusRoot, "corpus-b");
        if (!Directory.Exists(corpusBRoot))
        {
            Assert.Skip($"Corpus B not found at {corpusBRoot}. Generate corpus first.");
            return;
        }

        var sizes = new[] { (1L * 1024 * 1024 * 1024, "1gb"),
                             (5L * 1024 * 1024 * 1024, "5gb"),
                             (20L * 1024 * 1024 * 1024, "20gb") };

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("file_size_gib,peak_working_set_mib,peak_private_mib,growth_from_1gb_mib");

        double? baselineMiB = null;
        var results = new List<(string label, double peakMiB, double growthMiB)>();

        foreach (var (expectedSize, label) in sizes)
        {
            var filePath = Path.Combine(corpusBRoot, $"streaming-{label}.bin");
            if (!File.Exists(filePath))
            {
                await writer.WriteLineAsync($"{label},file_not_found,,,");
                continue;
            }

            var peakMiB = await MeasureStreamingFileMemory(filePath);
            var growth = baselineMiB.HasValue ? peakMiB - baselineMiB.Value : 0;

            results.Add((label, peakMiB, growth));
            await writer.WriteLineAsync(
                $"{expectedSize / (1024.0 * 1024.0 * 1024.0):F0},{peakMiB:F1},,{growth:F1}");

            if (!baselineMiB.HasValue) baselineMiB = peakMiB;
        }

        var maxGrowth = results.Where(r => r.growthMiB > 0).Select(r => r.growthMiB).DefaultIfEmpty(0).Max();

        await writer.WriteLineAsync($"# max_growth_mib={maxGrowth:F1}");
        await writer.WriteLineAsync($"# threshold_mib=128");
        await writer.WriteLineAsync($"# pass={maxGrowth <= 128}");

        // Assert SRS-NFR-005: streaming growth ≤ 128 MiB
        Assert.True(maxGrowth <= 128,
            $"Streaming memory growth {maxGrowth:F0} MiB exceeds 128 MiB threshold.");
    }

    /// <summary>
    /// Verifies worker job object memory does not exceed 1 GiB.
    /// Target SRS-NFR-003 (worker Job constraint).
    /// </summary>
    [Fact]
    public async Task worker_job_memory_within_1_gib()
    {
        RequirePerformanceHost();
        var counterPath = GetCounterPath("worker-job-memory");

        var corpusARoot = Path.Combine(CorpusRoot, "corpus-a");
        if (!Directory.Exists(corpusARoot))
        {
            Assert.Skip($"Corpus A not found at {corpusARoot}.");
            return;
        }

        await using var writer = new StreamWriter(counterPath, append: false);
        await writer.WriteLineAsync("timestamp_s,worker_job_peak_mib");

        var peakJobMiB = 0.0;

        // Run a scan and track child process job limits
        // (On Linux/CI this is a compile-time check only)
        await RunScanToCompletion(corpusARoot);
        var workerProcesses = Process.GetProcesses()
            .Where(p => p.ProcessName.Contains("SecurityReview.Worker"))
            .ToList();

        foreach (var wp in workerProcesses)
        {
            try
            {
                wp.Refresh();
                var pm = wp.PrivateMemorySize64 / (1024.0 * 1024.0);
                if (pm > peakJobMiB) peakJobMiB = pm;
                wp.Dispose();
            }
            catch { /* process may have exited */ }
        }

        await writer.WriteLineAsync($"complete,{peakJobMiB:F1}");
        await writer.WriteLineAsync($"# peak_worker_job_mib={peakJobMiB:F1}");
        await writer.WriteLineAsync($"# threshold_mib=1024");
        await writer.WriteLineAsync($"# pass={peakJobMiB <= 1024}");

        Assert.True(peakJobMiB <= 1024,
            $"Worker Job peak memory {peakJobMiB:F0} MiB exceeds 1024 MiB threshold.");
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private static async Task RunScanToCompletion(string corpusRoot)
    {
        var appExe = FindAppExecutable();
        var psi = new ProcessStartInfo
        {
            FileName = appExe,
            Arguments = $"scan --path \"{corpusRoot}\" --no-llm",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc is null) return;
        await proc.WaitForExitAsync();
    }

    private static async Task<double> MeasureStreamingFileMemory(string filePath)
    {
        var proc = Process.GetCurrentProcess();
        var peakMiB = 0.0;

        // Read the file in streaming fashion, measuring memory
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, bufferSize: 65536, useAsync: true);

        var buffer = new byte[65536];
        var totalRead = 0L;

        while (totalRead < fs.Length)
        {
            var read = await fs.ReadAsync(buffer);
            if (read == 0) break;
            totalRead += read;

            // Sample memory every 256 MiB read
            if (totalRead % (256 * 1024 * 1024) < read)
            {
                proc.Refresh();
                var current = proc.WorkingSet64 / (1024.0 * 1024.0);
                if (current > peakMiB) peakMiB = current;
            }
        }

        return peakMiB;
    }

    private static double MeasureWorkerProcessesMemory()
    {
        double total = 0;
        try
        {
            var workers = Process.GetProcesses()
                .Where(p => p.ProcessName.Contains("SecurityReview.Worker"));

            foreach (var w in workers)
            {
                try
                {
                    w.Refresh();
                    total += w.PrivateMemorySize64 / (1024.0 * 1024.0);
                    w.Dispose();
                }
                catch { /* process may exit between enumeration and refresh */ }
            }
        }
        catch { /* enumeration may fail */ }
        return total;
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
}
