using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.CorpusTool.Commands;

/// <summary>
/// Lightweight smoke-scan command. Accepts <c>--root &lt;path&gt;</c>,
/// scans every file in the directory tree, and writes JSON counts/status/hashes
/// to stdout. Never displays chunks or content.
/// </summary>
public static class ScanSmokeCommand
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async Task<int> RunAsync(string[] args)
    {
        string? root = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--root" && i + 1 < args.Length)
            {
                root = args[++i];
            }
        }

        if (root is null || !Directory.Exists(root))
        {
            await Console.Error.WriteLineAsync(
                "Usage: scan-smoke --root <path>");
            return 2;
        }

        // Register parsers.
        var parsers = new IFormatParser[]
        {
            new TextFormatParser(),
            new ZipFormatParser(),
            new TarFormatParser(),
            new GZipFormatParser(),
        };

        var runner = new Application.Scans.InProcessParserRunner(parsers);

        int processedCount = 0;
        int failedCount = 0;
        int chunkCount = 0;
        int gapCount = 0;
        int childCount = 0;
        long totalBytes = 0;
        var fileHashes = new Dictionary<string, string>();
        var failures = new List<string>();

        string[] files = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories);

        foreach (string filePath in files)
        {
            string relativePath = Path.GetRelativePath(root, filePath);
            long fileLength = new FileInfo(filePath).Length;
            FileId fileId = new(Guid.NewGuid());
            JobId jobId = new(Guid.NewGuid());
            ScanId scanId = new(Guid.NewGuid());

            var limits = Application.Scans.ScanScheduler.CreateOrdinaryLimits(
                DateTimeOffset.UtcNow);

            string formatHint = Path.GetExtension(filePath).ToLowerInvariant() switch
            {
                ".txt" or ".csv" or ".log" or ".md" or ".xml" or ".json"
                    or ".yaml" or ".yml" or ".ini" or ".cfg" or ".conf"
                    or ".html" or ".htm" or ".css" or ".js" or ".ts"
                    or ".py" or ".java" or ".cs" or ".c" or ".h" or ".cpp"
                    or ".hpp" or ".rs" or ".go" or ".rb" or ".php"
                    or ".sh" or ".bat" or ".ps1" or ".sql" => "text",
                ".zip" or ".jar" or ".apk" or ".epub" => "zip",
                ".gz" or ".tgz" => "gzip",
                ".tar" => "tar",
                _ => "unknown",
            };

            var item = new Application.Scans.ScanWorkItem(
                jobId, scanId, fileId, filePath, formatHint,
                fileLength, limits, IsOci: false);

            int fileChunks = 0;
            bool fileFailed = false;

            try
            {
                await foreach (Application.Scans.WorkerJobResult result in
                   runner.ProcessAsync(item, CancellationToken.None))
                {
                    switch (result.Kind)
                    {
                        case Application.Scans.WorkerResultKind.Chunk:
                            fileChunks++;
                            chunkCount++;
                            break;

                        case Application.Scans.WorkerResultKind.ChildDiscovered:
                            childCount++;
                            break;

                        case Application.Scans.WorkerResultKind.Gap:
                            gapCount++;
                            break;

                        case Application.Scans.WorkerResultKind.Completed:
                            processedCount++;
                            break;

                        case Application.Scans.WorkerResultKind.Failed:
                            fileFailed = true;
                            failedCount++;
                            if (result.Failure.HasValue)
                            {
                                failures.Add($"{relativePath}:{result.Failure}");
                            }

                            break;

                        case Application.Scans.WorkerResultKind.Cancelled:
                            fileFailed = true;
                            failedCount++;
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                fileFailed = true;
                failedCount++;
                failures.Add($"{relativePath}:{ex.GetType().Name}");
            }

            // Compute SHA-256 hash of the file.
            if (!fileFailed)
            {
                try
                {
                    await using FileStream fs = File.OpenRead(filePath);
                    byte[] hash = await SHA256.HashDataAsync(fs);
                    fileHashes[relativePath] = Convert.ToHexString(hash).ToLowerInvariant();
                    totalBytes += fileLength;
                }
                catch (Exception ex)
                {
                    failedCount++;
                    failures.Add($"{relativePath}:hash:{ex.GetType().Name}");
                    fileFailed = true;
                }
            }
        }

        string status = failedCount == 0 ? "completed"
            : processedCount > 0 ? "partial" : "failed";

        var output = new
        {
            status,
            discoveredFiles = files.Length,
            processedFiles = processedCount,
            failedFiles = failedCount,
            totalChunks = chunkCount,
            totalGaps = gapCount,
            totalChildren = childCount,
            totalBytes,
            fingerprints = fileHashes,
            failures = failures.Count > 0 ? failures : null,
        };

        string json = JsonSerializer.Serialize(output, JsonOptions);

        await Console.Out.WriteLineAsync(json);

        return status == "completed" ? 0 : 1;
    }
}
