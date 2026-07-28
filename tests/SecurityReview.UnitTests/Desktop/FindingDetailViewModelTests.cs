using System.Text;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using SecurityReview.UnitTests.Scans;

namespace SecurityReview.UnitTests.Desktop;

public sealed class FindingDetailViewModelTests : IDisposable
{
    private readonly string _tempDir =
        Directory.CreateTempSubdirectory("srt-fdetail-").FullName;

    // ---------------------------------------------------------- line/column

    [Fact]
    public void Compute_line_column_handles_lf()
    {
        (long line, long column) =
            FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 4);
        Assert.Equal(2, line);
        Assert.Equal(1, column);

        (line, column) = FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 5);
        Assert.Equal(2, line);
        Assert.Equal(2, column);

        (line, column) = FindingDetailViewModel.ComputeLineColumn("abc\ndef\nghi", 8);
        Assert.Equal(3, line);
        Assert.Equal(1, column);
    }

    [Fact]
    public void Compute_line_column_handles_crlf()
    {
        (long line, long column) =
            FindingDetailViewModel.ComputeLineColumn("abc\r\ndef", 5);
        Assert.Equal(2, line);
        Assert.Equal(1, column);
    }

    [Fact]
    public void Compute_line_column_counts_multibyte_characters()
    {
        // “你”= 3 UTF-8 字节；byteStart 4 指向第二行“好”。
        (long line, long column) =
            FindingDetailViewModel.ComputeLineColumn("你\n好", 4);
        Assert.Equal(2, line);
        Assert.Equal(1, column);
    }

    // ---------------------------------------------------------- detail loading

    [Fact]
    public async Task Load_detail_disables_open_buttons_when_file_is_missing()
    {
        (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
            BuildQuery(writeFile: false, nested: false);
        var viewModel = new FindingDetailViewModel(
            () => query,
            () => new ExplorerService(_ => false),
            new TestErrorSink());

        await viewModel.LoadDetailAsync(scanId, occurrenceId);

        Assert.True(viewModel.HasDetail);
        Assert.False(viewModel.FileExists);
        Assert.False(viewModel.LocateInExplorerCommand.CanExecute(null));
        Assert.False(viewModel.OpenExternallyCommand.CanExecute(null));
        Assert.Contains("不存在", viewModel.PreviewText);
    }

    [Fact]
    public async Task Load_detail_marks_nested_content_with_container_note()
    {
        (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
            BuildQuery(writeFile: true, nested: true);
        var viewModel = new FindingDetailViewModel(
            () => query,
            () => new ExplorerService(_ => false),
            new TestErrorSink());

        await viewModel.LoadDetailAsync(scanId, occurrenceId);

        Assert.True(viewModel.HasDetail);
        Assert.True(viewModel.IsNestedContainer);
        Assert.True(viewModel.FileExists);
        Assert.Contains("位于容器内", viewModel.PreviewText);
        Assert.True(viewModel.LocateInExplorerCommand.CanExecute(null));
    }

    [Fact]
    public async Task Load_detail_shows_preview_and_computed_line_column()
    {
        (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
            BuildQuery(writeFile: true, nested: false);
        var viewModel = new FindingDetailViewModel(
            () => query,
            () => new ExplorerService(_ => false),
            new TestErrorSink());

        await viewModel.LoadDetailAsync(scanId, occurrenceId);

        Assert.True(viewModel.HasDetail);
        Assert.Contains("secret-token", viewModel.PreviewText);
        Assert.Equal("第 2 行，第 1 列", viewModel.LineColumnDisplay);
        Assert.StartsWith("…", viewModel.FullPathDisplay);
        Assert.DoesNotContain(_tempDir, viewModel.FullPathDisplay);
    }

    [Fact]
    public async Task Windowed_preview_centers_hit_when_window_has_many_lines_before_hit()
    {
        // >4 MiB 文件触发窗口化预览；命中点距窗口起点 32 KiB，
        // 窗口内命中行之前有 512 行（>20 行片段上限）。
        // 文件真实行号：命中在第 70001 行。
        string fillerLine = new string('x', 63); // 含 \n 共 64 字节/行
        var sb = new StringBuilder(4_500_000);
        for (int i = 0; i < 70_000; i++)
            sb.Append(fillerLine).Append('\n');
        long byteStart = sb.Length; // 纯 ASCII：字符数 == UTF-8 字节数
        sb.Append("secret-token").Append('\n');
        sb.Append(fillerLine).Append('\n');

        (ScanQueryService query, ScanId scanId, FindingOccurrenceId occurrenceId) =
            BuildQuery(writeFile: true, nested: false,
                fileContent: sb.ToString(), byteStart: byteStart);
        var viewModel = new FindingDetailViewModel(
            () => query,
            () => new ExplorerService(_ => false),
            new TestErrorSink());

        await viewModel.LoadDetailAsync(scanId, occurrenceId);

        Assert.True(viewModel.HasDetail);
        Assert.Contains("大文件仅显示命中点附近片段", viewModel.PreviewText);
        Assert.Equal("第 70001 行，第 1 列", viewModel.LineColumnDisplay);

        // 命中行必须在片段内且被高亮，而不是锚定到窗口首行。
        Assert.Contains("secret-token", viewModel.PreviewText);
        Assert.Contains("前面省略", viewModel.PreviewText);
        string[] previewLines = viewModel.PreviewText.Split('\n');
        int hitIndex = Array.FindIndex(previewLines,
            l => l.Contains("secret-token", StringComparison.Ordinal));
        Assert.True(hitIndex >= 0);
        Assert.StartsWith("▶", previewLines[hitIndex]);
        Assert.Contains(" 70001 │", previewLines[hitIndex]);
    }

    [Fact]
    public void External_open_returns_false_when_confirmation_is_declined()
    {
        string file = Path.Combine(_tempDir, "exists.txt");
        File.WriteAllText(file, "data");
        var explorer = new ExplorerService(_ => false);

        Assert.False(explorer.OpenExternally(file));
    }

    [Fact]
    public void External_open_returns_false_for_missing_file_without_asking()
    {
        bool asked = false;
        var explorer = new ExplorerService(_ =>
        {
            asked = true;
            return true;
        });

        Assert.False(explorer.OpenExternally(
            Path.Combine(_tempDir, "missing.txt")));
        Assert.False(asked);
    }

    // ---------------------------------------------------------- helpers

    private (ScanQueryService, ScanId, FindingOccurrenceId) BuildQuery(
        bool writeFile,
        bool nested,
        string? fileContent = null,
        long byteStart = 6,
        long byteLength = 12)
    {
        ScanId scanId = new(Guid.NewGuid());
        FindingGroupId groupId = new(Guid.NewGuid());
        FindingOccurrenceId occurrenceId = new(Guid.NewGuid());
        string fileHash = new string('a', 64);

        string relativePath = nested ? "bundle.zip" : "hit.txt";
        string virtualPath = nested ? "bundle.zip!inner/secret.txt" : "hit.txt";
        SourceLocator locator = nested
            ? new SourceLocator.NestedLocator(
                "bundle.zip", new SourceLocator.TextLocator(0, 0, 0, 12))
            : new SourceLocator.TextLocator(0, 0, byteStart, byteLength);

        if (writeFile)
        {
            string content = fileContent
                ?? (nested ? "PK-zip-bytes" : "alpha\nsecret-token\nomega\n");
            File.WriteAllText(Path.Combine(_tempDir, relativePath), content);
        }

        var occurrence = new FindingOccurrence(
            occurrenceId,
            groupId,
            "raw-secret",
            "raw-context",
            locator,
            virtualPath,
            fileHash,
            []);
        var group = new FindingGroup(
            groupId,
            FindingKind.SensitiveContent,
            Severity.High,
            new ValueFingerprint(new string('b', 64)),
            [occurrence]);
        var file = new FileRecord(
            new FileId(Guid.NewGuid()),
            0,
            relativePath,
            null,
            null,
            64,
            DateTimeOffset.UnixEpoch,
            FileAttributes.Normal,
            new FileStreamIdentity("volume", 1, null),
            [],
            InventoryStatus.Complete,
            "text",
            fileHash,
            CoverageStatus.Covered);

        var protector = new FakePayloadProtector();
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Completed, now, now,
            "rules", "client", "pipeline", 1, 1);
        var query = new ScanQueryService(
            new FakeScanRepository(scan),
            new FakeFindingRepository(scanId, [group]),
            new FakeCoverageRepository(),
            new FakeFileRepository(scanId, [file]),
            new FakeReviewService(),
            new FakeScanSnapshotRepository(
                ScanTestData.BuildRecord(scanId, protector, _tempDir)),
            protector);
        return (query, scanId, occurrenceId);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch (IOException) { }
    }

    private sealed class TestErrorSink : IUiErrorSink
    {
        public void Report(string code, string message)
        {
        }
    }
}
