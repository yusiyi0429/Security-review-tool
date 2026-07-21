using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the sensitive finding detail display.
/// Selects a specific occurrence and decrypts only that detail.
/// Navigating away or closing clears all string references.
/// Copy Full Value requires explicit button + confirmation;
/// clipboard auto-clears after 60 seconds.
/// </summary>
public sealed class FindingDetailViewModel : ObservableObject, IDisposable
{
    private readonly Func<ScanQueryService> _queryFactory;
    private readonly Func<ExplorerService> _explorerFactory;
    private readonly IUiErrorSink _errorSink;

    private DisposableOccurrenceDetail? _currentDetail;
    private string _virtualPath = "";
    private string _locatorDisplay = "";
    private string _fileHash = "";
    private string _decryptedValue = "";
    private string _decryptedContext = "";
    private bool _hasDetail;
    private bool _isLoading;

    private DateTimeOffset _clipboardSetAt;
    private string? _clipboardFingerprint;
    private System.Timers.Timer? _clipboardTimer;
    private const int ClipboardAutoClearSeconds = 60;

    public FindingDetailViewModel(
        Func<ScanQueryService> queryFactory,
        Func<ExplorerService> explorerFactory,
        IUiErrorSink errorSink)
    {
        _queryFactory = queryFactory;
        _explorerFactory = explorerFactory;
        _errorSink = errorSink;

        CopyFullValueCommand = new RelayCommand(_ => CopyFullValue(), _ => HasDetail);
        CopyLocatorCommand = new RelayCommand(_ => CopyLocator(), _ => HasDetail);
        LocateInExplorerCommand = new RelayCommand(_ => LocateInExplorer(), _ => HasDetail);
        OpenExternallyCommand = new RelayCommand(_ => OpenExternally(), _ => HasDetail);
        ClearDetailCommand = new RelayCommand(_ => ClearDetail());
    }

    // ------------------------------------------------------------------ Commands

    public ICommand CopyFullValueCommand { get; }
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

    public string LocatorDisplay
    {
        get => _locatorDisplay;
        private set => SetProperty(ref _locatorDisplay, value);
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

    // ------------------------------------------------------------------ Detail loading

    /// <summary>
    /// Loads and decrypts the detail for a specific occurrence.
    /// Previous detail is cleared before the new one is loaded.
    /// </summary>
    public async Task LoadDetailAsync(FindingOccurrenceId occurrenceId, CancellationToken ct = default)
    {
        ClearDetailInternal();

        IsLoading = true;
        try
        {
            var query = _queryFactory();
            var detail = await query.GetOccurrenceDetailsAsync(occurrenceId, ct).ConfigureAwait(true);
            if (detail is null)
            {
                _errorSink.Report("detail_not_found", $"未找到发现出现的详情: {occurrenceId.Value}");
                return;
            }

            _currentDetail = detail;
            VirtualPath = detail.VirtualPath;
            LocatorDisplay = detail.CanonicalLocator.ToCanonicalDisplay();
            FileHash = detail.FileSha256.Length >= 16 ? detail.FileSha256[..16] : detail.FileSha256;

            // Decrypt and display the sensitive value and context ONCE
            DecryptedValue = detail.SensitiveValue.Value;
            DecryptedContext = detail.SensitiveContext.Value;

            HasDetail = true;
        }
        catch (Exception)
        {
            _errorSink.Report("detail_load_failed", $"加载发现详情失败。");
        }
        finally
        {
            IsLoading = false;
        }
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

    private void CopyLocator()
    {
        if (!HasDetail) return;
        Clipboard.SetText(_locatorDisplay);
    }

    private void LocateInExplorer()
    {
        if (!HasDetail) return;
        var explorer = _explorerFactory();
        string outerPath = ExplorerService.ResolveOuterPath(_virtualPath, _virtualPath);
        if (!ExplorerService.LocateInExplorer(outerPath))
        {
            _errorSink.Report("explorer_failed", $"无法定位文件: {outerPath}");
        }
    }

    private void OpenExternally()
    {
        if (!HasDetail) return;
        var explorer = _explorerFactory();
        string outerPath = ExplorerService.ResolveOuterPath(_virtualPath, _virtualPath);
        explorer.OpenExternally(outerPath);
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
        LocatorDisplay = "";
        FileHash = "";

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
