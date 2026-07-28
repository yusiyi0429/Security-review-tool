using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the sensitive finding detail display.
/// Selects a specific occurrence within one scan and decrypts only that
/// detail. Resolves the on-disk location through the scan configuration
/// snapshot (never by treating the virtual path as a file-system path),
/// renders a bounded safe preview, and locates/opens the file only via
/// ExplorerService (external open always re-confirms).
/// Navigating away or closing clears all string references.
/// Copy Full Value requires explicit button + confirmation;
/// clipboard auto-clears after 60 seconds.
/// </summary>
public sealed class FindingDetailViewModel : ObservableObject, IDisposable
{
    private const long MaxFullReadBytes = 4 * 1024 * 1024; // 4 MiB
    private const int PreviewWindowBytes = 65_536;         // 与 SafePreviewService 上限一致
    private const int ClipboardAutoClearSeconds = 60;

    private readonly Func<ScanQueryService> _queryFactory;
    private readonly Func<ExplorerService> _explorerFactory;
    private readonly IUiErrorSink _errorSink;

    private DisposableOccurrenceDetail? _currentDetail;
    private string? _absolutePath;
    private string _virtualPath = "";
    private string _fullPathDisplay = "";
    private string _locatorDisplay = "";
    private string _lineColumnDisplay = "";
    private string _fileHash = "";
    private string _decryptedValue = "";
    private string _decryptedContext = "";
    private string _previewText = "";
    private bool _hasDetail;
    private bool _isLoading;
    private bool _fileExists;
    private bool _isNestedContainer;

    private DateTimeOffset _clipboardSetAt;
    private string? _clipboardFingerprint;
    private System.Timers.Timer? _clipboardTimer;

    public FindingDetailViewModel(
        Func<ScanQueryService> queryFactory,
        Func<ExplorerService> explorerFactory,
        IUiErrorSink errorSink)
    {
        _queryFactory = queryFactory;
        _explorerFactory = explorerFactory;
        _errorSink = errorSink;

        CopyFullValueCommand = new RelayCommand(_ => CopyFullValue(), _ => HasDetail);
        CopyFullPathCommand = new RelayCommand(
            _ => CopyFullPath(), _ => HasDetail && _absolutePath is not null);
        CopyLocatorCommand = new RelayCommand(_ => CopyLocator(), _ => HasDetail);
        LocateInExplorerCommand = new RelayCommand(
            _ => LocateInExplorer(), _ => HasDetail && FileExists);
        OpenExternallyCommand = new RelayCommand(
            _ => OpenExternally(), _ => HasDetail && FileExists);
        ClearDetailCommand = new RelayCommand(_ => ClearDetail());
    }

    // ------------------------------------------------------------------ Commands

    public ICommand CopyFullValueCommand { get; }
    public ICommand CopyFullPathCommand { get; }
    public ICommand CopyLocatorCommand { get; }
    public ICommand LocateInExplorerCommand { get; }
    public ICommand OpenExternallyCommand { get; }
    public ICommand ClearDetailCommand { get; }

    // ------------------------------------------------------------------ Properties

    public string VirtualPath
    {
        get => _virtualPath;
        private set => SetProperty(ref _virtualPath, value);
    }

    public string FullPathDisplay
    {
        get => _fullPathDisplay;
        private set => SetProperty(ref _fullPathDisplay, value);
    }

    public string LocatorDisplay
    {
        get => _locatorDisplay;
        private set => SetProperty(ref _locatorDisplay, value);
    }

    public string LineColumnDisplay
    {
        get => _lineColumnDisplay;
        private set => SetProperty(ref _lineColumnDisplay, value);
    }

    public string FileHash
    {
        get => _fileHash;
        private set => SetProperty(ref _fileHash, value);
    }

    public string DecryptedValue
    {
        get => _decryptedValue;
        private set => SetProperty(ref _decryptedValue, value);
    }

    public string DecryptedContext
    {
        get => _decryptedContext;
        private set => SetProperty(ref _decryptedContext, value);
    }

    public string PreviewText
    {
        get => _previewText;
        private set => SetProperty(ref _previewText, value);
    }

    public bool HasDetail
    {
        get => _hasDetail;
        set => SetProperty(ref _hasDetail, value);
    }

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public bool FileExists
    {
        get => _fileExists;
        private set => SetProperty(ref _fileExists, value);
    }

    public bool IsNestedContainer
    {
        get => _isNestedContainer;
        private set => SetProperty(ref _isNestedContainer, value);
    }

    // ------------------------------------------------------------------ Detail loading

    /// <summary>
    /// Loads and decrypts the detail for a specific occurrence within the
    /// given scan, then resolves its on-disk location and safe preview.
    /// Previous detail is cleared before the new one is loaded.
    /// </summary>
    public async Task LoadDetailAsync(
        ScanId scanId,
        FindingOccurrenceId occurrenceId,
        CancellationToken ct = default)
    {
        ClearDetailInternal();

        IsLoading = true;
        try
        {
            var query = _queryFactory();
            var detail = await query
                .GetOccurrenceDetailsAsync(scanId, occurrenceId, ct)
                .ConfigureAwait(true);
            if (detail is null)
            {
                _errorSink.Report("detail_not_found", "未找到发现出现的详情。");
                return;
            }

            _currentDetail = detail;
            VirtualPath = detail.VirtualPath;
            LocatorDisplay = detail.CanonicalLocator.ToCanonicalDisplay();
            FileHash = detail.FileSha256.Length >= 16
                ? detail.FileSha256[..16]
                : detail.FileSha256;

            // Decrypt and display the sensitive value and context ONCE
            DecryptedValue = detail.SensitiveValue.Value;
            DecryptedContext = detail.SensitiveContext.Value;

            OccurrenceFileLocation? location = await query
                .GetOccurrenceFileLocationAsync(scanId, occurrenceId, ct)
                .ConfigureAwait(true);
            if (location is not null)
            {
                _absolutePath = location.AbsolutePath;
                FileExists = location.FileExists;
                IsNestedContainer = location.IsNested;
                FullPathDisplay = location.AbsolutePath is null
                    ? "（无法还原绝对路径）"
                    : RedactAbsolutePath(location.AbsolutePath);

                if (location.AbsolutePath is not null && location.FileExists)
                {
                    await BuildPreviewAsync(location.AbsolutePath, location)
                        .ConfigureAwait(true);
                }
                else if (location.AbsolutePath is not null)
                {
                    PreviewText = "（文件已不存在，无法预览。）";
                }
                else
                {
                    PreviewText = "（无法还原文件位置，预览不可用。）";
                }
            }
            else
            {
                FullPathDisplay = "（无法还原绝对路径）";
                PreviewText = "（无法还原文件位置，预览不可用。）";
            }

            HasDetail = true;
        }
        catch (Exception)
        {
            _errorSink.Report("detail_load_failed", "加载发现详情失败。");
        }
        finally
        {
            IsLoading = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    // ------------------------------------------------------------------ Preview

    /// <summary>
    /// Computes the 1-based line and character column for a UTF-8 byte
    /// offset inside decoded text. Handles LF and CRLF line endings.
    /// </summary>
    public static (long Line, long Column) ComputeLineColumn(
        string text, long byteStart)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (byteStart < 0)
            byteStart = 0;

        long consumed = 0;
        long line = 1;
        long column = 1;
        for (int i = 0; i < text.Length; i++)
        {
            if (consumed >= byteStart)
                break;

            char c = text[i];
            int charLength = char.IsHighSurrogate(c)
                && i + 1 < text.Length
                && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            consumed += Encoding.UTF8.GetByteCount(text.AsSpan(i, charLength));
            if (c == '\n')
            {
                line++;
                column = 1;
            }
            else
            {
                column++;
            }
            i += charLength - 1;
        }
        return (line, column);
    }

    private async Task BuildPreviewAsync(
        string absolutePath, OccurrenceFileLocation location)
    {
        if (location.IsNested)
        {
            PreviewText = $"位于容器内：{location.VirtualPath}\n" +
                "嵌套内容不支持应用内预览，请用“在资源管理器中定位”查看外层容器。";
            return;
        }

        try
        {
            var info = new FileInfo(absolutePath);
            if (info.Length > MaxFullReadBytes)
            {
                await BuildWindowedPreviewAsync(absolutePath, location)
                    .ConfigureAwait(true);
                return;
            }

            string fullText = await File.ReadAllTextAsync(absolutePath)
                .ConfigureAwait(true);

            SourceLocator previewLocator = location.CanonicalLocator;
            if (location.CanonicalLocator is SourceLocator.TextLocator textLocator)
            {
                (long line, long column) =
                    ComputeLineColumn(fullText, textLocator.ByteStart);
                LineColumnDisplay = string.Create(
                    CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");
                // 存储的 TextLocator.Line 恒为 0；用现算行号定位预览片段。
                previewLocator = new SourceLocator.TextLocator(
                    line - 1, column - 1,
                    textLocator.ByteStart, textLocator.ByteLength);
            }
            else if (location.CanonicalLocator is SourceLocator.JsonLocator jsonLocator)
            {
                (long line, long column) =
                    ComputeLineColumn(fullText, jsonLocator.ByteStart);
                LineColumnDisplay = string.Create(
                    CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");
            }

            SafePreviewFragment fragment =
                SafePreviewService.PreviewText(fullText, previewLocator);
            PreviewText = FormatFragment(fragment);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            PreviewText = "（无法读取文件进行预览：权限不足或文件被占用。）";
        }
    }

    private async Task BuildWindowedPreviewAsync(
        string absolutePath, OccurrenceFileLocation location)
    {
        (long byteStart, long byteLength) = location.CanonicalLocator switch
        {
            SourceLocator.TextLocator tl => (tl.ByteStart, tl.ByteLength),
            SourceLocator.JsonLocator jl => (jl.ByteStart, jl.ByteLength),
            _ => (0L, 0L),
        };

        long windowStart = Math.Max(0, byteStart - PreviewWindowBytes / 2);
        (long line, long column, long windowLine) =
            await ComputeLineColumnStreamingAsync(absolutePath, byteStart, windowStart)
                .ConfigureAwait(true);
        LineColumnDisplay = string.Create(
            CultureInfo.InvariantCulture, $"第 {line} 行，第 {column} 列");

        string windowText = await ReadWindowAsync(
            absolutePath, windowStart, PreviewWindowBytes)
            .ConfigureAwait(true);
        var windowLocator = new SourceLocator.TextLocator(
            line - windowLine, 0, byteStart - windowStart, byteLength);
        SafePreviewFragment fragment =
            SafePreviewService.PreviewText(windowText, windowLocator);
        PreviewText = "（大文件仅显示命中点附近片段，行号为文件真实行号。）\n"
            + FormatFragment(fragment, windowLine - 1);
    }

    private static async Task<(long Line, long Column, long WindowLine)>
        ComputeLineColumnStreamingAsync(
            string path, long byteStart, long windowStart)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[81_920];
        long consumed = 0;
        long line = 1;
        long lineStartByte = 0;
        long windowLine = 1;
        while (consumed < byteStart)
        {
            int read = await stream.ReadAsync(buffer, CancellationToken.None)
                .ConfigureAwait(true);
            if (read == 0)
                break;
            for (int i = 0; i < read && consumed < byteStart; i++, consumed++)
            {
                if (buffer[i] == (byte)'\n')
                {
                    line++;
                    lineStartByte = consumed + 1;
                }
                if (consumed == windowStart)
                    windowLine = line;
            }
        }
        return (line, byteStart - lineStartByte + 1, windowLine);
    }

    private static async Task<string> ReadWindowAsync(
        string path, long windowStart, int windowBytes)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        stream.Seek(windowStart, SeekOrigin.Begin);
        var buffer = new byte[windowBytes];
        int read = await stream.ReadAsync(buffer, CancellationToken.None)
            .ConfigureAwait(true);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static string FormatFragment(
        SafePreviewFragment fragment, long lineNumberOffset = 0)
    {
        var sb = new StringBuilder();
        if (fragment.TruncatedBefore > 0)
        {
            sb.Append("… 前面省略 ")
                .Append(fragment.TruncatedBefore.ToString(CultureInfo.InvariantCulture))
                .AppendLine(" 行 …");
        }
        for (int i = 0; i < fragment.Lines.Count; i++)
        {
            SafePreviewLine previewLine = fragment.Lines[i];
            string marker = i == fragment.HighlightLineIndex ? "▶" : " ";
            sb.Append(marker).Append(' ')
                .Append((previewLine.LineNumber + 1 + lineNumberOffset)
                    .ToString(CultureInfo.InvariantCulture))
                .Append(" │ ").AppendLine(previewLine.Text);
        }
        if (fragment.TruncatedAfter > 0)
        {
            sb.Append("… 后面省略 ")
                .Append(fragment.TruncatedAfter.ToString(CultureInfo.InvariantCulture))
                .Append(" 行 …");
        }
        return sb.ToString();
    }

    private static string RedactAbsolutePath(string absolutePath)
    {
        string leaf = Path.GetFileName(absolutePath);
        return leaf.Length == 0 ? "…" : $"…\\{leaf}";
    }

    // ------------------------------------------------------------------ Actions

    /// <summary>
    /// Copy Full Value requires explicit button press and confirmation.
    /// Sets a 60s clipboard auto-clear timer.
    /// </summary>
    private void CopyFullValue()
    {
        if (!HasDetail || string.IsNullOrEmpty(_decryptedValue)) return;

        var result = MessageBox.Show(
            "完整敏感值将被复制到剪贴板。\n\n剪贴板将在60秒后自动清除。\n确定要继续吗？",
            "复制完整值",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        Clipboard.SetText(_decryptedValue);
        _clipboardSetAt = DateTimeOffset.UtcNow;
        _clipboardFingerprint = _decryptedValue;

        // Start 60s auto-clear timer
        _clipboardTimer?.Stop();
        _clipboardTimer = new System.Timers.Timer(ClipboardAutoClearSeconds * 1000);
        _clipboardTimer.Elapsed += (_, _) =>
        {
            System.Windows.Application.Current?.Dispatcher.Invoke(() =>
            {
                if (Clipboard.ContainsText())
                {
                    string? current = null;
                    try { current = Clipboard.GetText(); } catch { }
                    if (current == _clipboardFingerprint)
                    {
                        Clipboard.Clear();
                    }
                }
                _clipboardTimer?.Stop();
            });
        };
        _clipboardTimer.AutoReset = false;
        _clipboardTimer.Start();
    }

    private void CopyFullPath()
    {
        if (!HasDetail || _absolutePath is null) return;
        Clipboard.SetText(_absolutePath);
    }

    private void CopyLocator()
    {
        if (!HasDetail) return;
        Clipboard.SetText(_locatorDisplay);
    }

    private void LocateInExplorer()
    {
        if (!HasDetail || !FileExists || _absolutePath is null) return;
        if (!ExplorerService.LocateInExplorer(_absolutePath))
        {
            _errorSink.Report("explorer_failed", "无法在资源管理器中定位该文件。");
        }
    }

    private void OpenExternally()
    {
        if (!HasDetail || !FileExists || _absolutePath is null) return;
        var explorer = _explorerFactory();
        explorer.OpenExternally(_absolutePath);
    }

    // ------------------------------------------------------------------ Cleanup

    /// <summary>
    /// Clears the current detail. Zeroes all sensitive string references.
    /// Called on navigation, close, or explicit clear.
    /// </summary>
    public void ClearDetail()
    {
        ClearDetailInternal();
        HasDetail = false;
    }

    private void ClearDetailInternal()
    {
        // Dispose the sensitive strings (zeroes the buffers)
        _currentDetail?.SensitiveValue.Dispose();
        _currentDetail?.SensitiveContext.Dispose();
        _currentDetail = null;

        // Clear all string properties
        DecryptedValue = "";
        DecryptedContext = "";
        VirtualPath = "";
        FullPathDisplay = "";
        LocatorDisplay = "";
        LineColumnDisplay = "";
        FileHash = "";
        PreviewText = "";
        _absolutePath = null;
        FileExists = false;
        IsNestedContainer = false;

        // Stop clipboard timer
        _clipboardTimer?.Stop();
        _clipboardTimer = null;
        _clipboardFingerprint = null;
    }

    public void Dispose()
    {
        ClearDetailInternal();
        _clipboardTimer?.Dispose();
    }
}

// ---------------------------------------------------------------------------
// Simple synchronous relay command for non-async operations
// ---------------------------------------------------------------------------

file sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
}
