using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;

namespace SecurityReview.IntegrationTests.Scans;

public sealed class TextArchiveScanTests
{
    [Fact]
    public async Task valid_text_file_produces_chunks_and_completes()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-scan-text-");
        try
        {
            // Create a simple text file.
            string filePath = Path.Combine(root.FullName, "sample.txt");
            await File.WriteAllTextAsync(filePath, "Hello, world!\nThis is a test file.\n",
                TestContext.Current.CancellationToken);

            var parsers = new IFormatParser[]
            {
                new TextFormatParser(),
                new ZipFormatParser(),
                new TarFormatParser(),
                new GZipFormatParser(),
            };

            var runner = new InProcessParserRunner(parsers);

            FileId fileId = new(Guid.NewGuid());
            JobId jobId = new(Guid.NewGuid());
            ScanId scanId = new(Guid.NewGuid());

            var item = new ScanWorkItem(
                jobId, scanId, fileId, filePath, "text",
                new FileInfo(filePath).Length,
                ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
                IsOci: false);

            int chunkCount = 0;
            bool completed = false;

            await foreach (WorkerJobResult result in runner.ProcessAsync(
                item, TestContext.Current.CancellationToken))
            {
                switch (result.Kind)
                {
                    case WorkerResultKind.Chunk:
                        chunkCount++;
                        Assert.NotNull(result.Chunk);
                        Assert.Equal(ContentKind.Text, result.Chunk!.ContentKind);
                        Assert.NotEmpty(result.Chunk.Text);
                        break;

                    case WorkerResultKind.Completed:
                        completed = true;
                        break;

                    case WorkerResultKind.Failed:
                        Assert.Fail($"Unexpected failure: {result.Failure}");
                        break;
                }
            }

            Assert.True(completed);
            Assert.True(chunkCount > 0);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task nested_archive_discovers_children()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-scan-archive-");
        try
        {
            // Create a text file and zip it.
            string innerPath = Path.Combine(root.FullName, "inner.txt");
            await File.WriteAllTextAsync(innerPath, "archive content",
                TestContext.Current.CancellationToken);

            string zipPath = Path.Combine(root.FullName, "test.zip");
            System.IO.Compression.ZipFile.CreateFromDirectory(
                root.FullName, zipPath);

            var parsers = new IFormatParser[]
            {
                new TextFormatParser(),
                new ZipFormatParser(),
                new TarFormatParser(),
                new GZipFormatParser(),
            };

            var runner = new InProcessParserRunner(parsers);

            FileId fileId = new(Guid.NewGuid());
            JobId jobId = new(Guid.NewGuid());
            ScanId scanId = new(Guid.NewGuid());

            var item = new ScanWorkItem(
                jobId, scanId, fileId, zipPath, "zip",
                new FileInfo(zipPath).Length,
                ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
                IsOci: false);

            bool childDiscovered = false;
            bool completed = false;

            await foreach (WorkerJobResult result in runner.ProcessAsync(
                item, TestContext.Current.CancellationToken))
            {
                switch (result.Kind)
                {
                    case WorkerResultKind.ChildDiscovered:
                        childDiscovered = true;
                        Assert.NotNull(result.ChildVirtualPath);
                        Assert.NotNull(result.ChildProbe);
                        break;

                    case WorkerResultKind.Completed:
                        completed = true;
                        break;

                    case WorkerResultKind.Failed:
                        Assert.Fail($"Unexpected failure: {result.Failure}");
                        break;
                }
            }

            Assert.True(completed);
            Assert.True(childDiscovered);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task corrupt_sibling_produces_gap_and_continues()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-scan-corrupt-");
        try
        {
            // Create a binary file that looks like garbage.
            string corruptPath = Path.Combine(root.FullName, "corrupt.bin");
            byte[] randomBytes = new byte[1024];
            new Random(42).NextBytes(randomBytes);
            await File.WriteAllBytesAsync(corruptPath, randomBytes,
                TestContext.Current.CancellationToken);

            var parsers = new IFormatParser[]
            {
                new TextFormatParser(),
                new ZipFormatParser(),
            };

            var runner = new InProcessParserRunner(parsers);

            FileId fileId = new(Guid.NewGuid());
            JobId jobId = new(Guid.NewGuid());
            ScanId scanId = new(Guid.NewGuid());

            var item = new ScanWorkItem(
                jobId, scanId, fileId, corruptPath, "unknown",
                new FileInfo(corruptPath).Length,
                ScanScheduler.CreateOrdinaryLimits(DateTimeOffset.UtcNow),
                IsOci: false);

            bool hasGap = false;

            await foreach (WorkerJobResult result in runner.ProcessAsync(
                item, TestContext.Current.CancellationToken))
            {
                if (result.Kind is WorkerResultKind.Gap or WorkerResultKind.Failed)
                {
                    hasGap = true;
                }
            }

            Assert.True(hasGap, "Corrupt file should produce a gap or failure.");
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }
}
