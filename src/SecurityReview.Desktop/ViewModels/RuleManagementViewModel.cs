using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SecurityReview.Application.Rules;
using SecurityReview.Desktop.Services;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Validation;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the rule pack management view.
/// Import ZIP, display signer/version/hash/errors/summary.
/// Active/old/local warnings. Never accepts raw Excel.
/// </summary>
public sealed class RuleManagementViewModel : ObservableObject
{
    private readonly Func<RulePackImportService> _importFactory;
    private readonly Func<IRulePackStore>? _storeFactory;
    private readonly IUiErrorSink _errorSink;
    private readonly Func<Task>? _configurationChanged;

    private string _activeRulePackId = "";
    private string _activeVersion = "";
    private string _activeHash = "";
    private string _activeSigner = "";
    private bool _hasActivePack;

    private ObservableCollection<RulePackHistoryItem> _history = new();
    private string _warnings = "";
    private string _lastImportStatus = "";
    private bool _isImporting;

    public RuleManagementViewModel(
        Func<RulePackImportService> importFactory,
        IUiErrorSink errorSink,
        Func<IRulePackStore>? storeFactory = null,
        Func<Task>? configurationChanged = null)
    {
        _importFactory = importFactory;
        _storeFactory = storeFactory;
        _errorSink = errorSink;
        _configurationChanged = configurationChanged;

        ImportCommand = new AsyncRelayCommand(_ => ImportRulePackAsync(), errorSink,
            _ => !IsImporting);
        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), errorSink);

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(IsImporting))
                CommandManager.InvalidateRequerySuggested();
        };
    }

    // ------------------------------------------------------------------ Commands

    public ICommand ImportCommand { get; }
    public ICommand RefreshCommand { get; }

    // ------------------------------------------------------------------ Properties

    public string ActiveRulePackId
    {
        get => _activeRulePackId;
        set => SetProperty(ref _activeRulePackId, value);
    }

    public string ActiveVersion
    {
        get => _activeVersion;
        set => SetProperty(ref _activeVersion, value);
    }

    public string ActiveHash
    {
        get => _activeHash;
        set => SetProperty(ref _activeHash, value);
    }

    public string ActiveSigner
    {
        get => _activeSigner;
        set => SetProperty(ref _activeSigner, value);
    }

    public bool HasActivePack
    {
        get => _hasActivePack;
        set => SetProperty(ref _hasActivePack, value);
    }

    public ObservableCollection<RulePackHistoryItem> History
    {
        get => _history;
        set => SetProperty(ref _history, value);
    }

    public string Warnings
    {
        get => _warnings;
        set => SetProperty(ref _warnings, value);
    }

    public string LastImportStatus
    {
        get => _lastImportStatus;
        set => SetProperty(ref _lastImportStatus, value);
    }

    public bool IsImporting
    {
        get => _isImporting;
        set => SetProperty(ref _isImporting, value);
    }

    // ------------------------------------------------------------------ Actions

    /// <summary>
    /// Opens a file picker for .zip files and imports the selected rule pack.
    /// Never accepts raw Excel files.
    /// </summary>
    private async Task ImportRulePackAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "导入规则包",
            Filter = "Rule Pack ZIP (*.zip)|*.zip|All Files (*.*)|*.*",
            DefaultExt = ".zip",
            CheckFileExists = true,
            Multiselect = false,
        };

        bool? result = dialog.ShowDialog();
        if (result != true) return;

        string filePath = dialog.FileName;

        // Reject non-ZIP files (never accept raw Excel)
        string ext = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
        if (ext is ".xlsx" or ".xls" or ".xlsm" or ".xlsb")
        {
            MessageBox.Show("不支持直接导入 Excel 文件。\n请导入由规则发布者签名的 .zip 格式规则包。", "格式不支持",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        IsImporting = true;
        LastImportStatus = "正在导入…";
        try
        {
            byte[] zipBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            var importService = _importFactory();

            var command = new ImportRulePackCommand { ZipBytes = zipBytes, AllowDowngrade = false };
            var importResult = await importService.ImportAsync(command, CancellationToken.None);

            if (importResult.Success)
            {
                var manifest = importResult.Validation?.Manifest;
                ActiveRulePackId = manifest?.RulePackId ?? "";
                ActiveVersion = manifest?.Version ?? "";
                ActiveHash = manifest is not null ? importResult.Validation?.PackageSha256 ?? "" : "";
                ActiveSigner = "";  // Signer info not exposed in ValidationSummary
                HasActivePack = true;
                LastImportStatus = $"导入成功 — {ActiveRulePackId} v{ActiveVersion}";

                // Add to history
                _history.Insert(0, new RulePackHistoryItem(
                    manifest?.RulePackId ?? "",
                    manifest?.Version ?? "",
                    importResult.Validation?.PackageSha256?[..16] ?? "",
                    "active",
                    DateTimeOffset.UtcNow));

                Warnings = "";
                if (_configurationChanged is not null)
                    await _configurationChanged();
            }
            else
            {
                LastImportStatus = $"导入失败: {importResult.ErrorMessage}";
                Warnings = $"验证错误: {importResult.ErrorMessage}";

                // Add failed import to history
                _history.Insert(0, new RulePackHistoryItem(
                    importResult.Validation?.Manifest?.RulePackId ?? "未知",
                    importResult.Validation?.Manifest?.Version ?? "未知",
                    "",
                    "import_failed",
                    DateTimeOffset.UtcNow));
            }
        }
        catch (Exception)
        {
            _errorSink.Report("rule_import_failed", $"规则包导入失败。");
            LastImportStatus = "导入失败 — 请检查文件是否有效。";
        }
        finally
        {
            IsImporting = false;
        }
    }

    public async Task RefreshAsync()
    {
        if (_storeFactory is null)
            return;

        try
        {
            ActivePointer? active = await _storeFactory()
                .GetActiveAsync(CancellationToken.None);
            if (active is null)
            {
                ActiveRulePackId = "";
                ActiveVersion = "";
                ActiveHash = "";
                HasActivePack = false;
                LastImportStatus = "尚未激活规则包";
                Warnings = "请导入由可信发布者签名的规则包后再开始扫描。";
                if (_configurationChanged is not null)
                    await _configurationChanged();
                return;
            }

            ActiveRulePackId = active.RulePackId;
            ActiveVersion = active.Version;
            ActiveHash = active.Sha256;
            HasActivePack = true;
            LastImportStatus = $"当前使用 — {active.RulePackId} v{active.Version}";
            Warnings = "";
            if (_configurationChanged is not null)
                await _configurationChanged();
        }
        catch (Exception)
        {
            HasActivePack = false;
            LastImportStatus = "规则包状态加载失败";
            Warnings = "无法读取当前活动规则包，请重新导入有效的签名规则包。";
            _errorSink.Report(
                "rule_pack_status_load_failed",
                "读取当前活动规则包失败。");
        }
    }
}

// ---------------------------------------------------------------------------
// Display item types
// ---------------------------------------------------------------------------

public sealed record RulePackHistoryItem(
    string RulePackId,
    string Version,
    string HashPrefix,
    string Status,
    DateTimeOffset ImportedAt)
{
    public string StatusDisplay => Status switch
    {
        "active" => "当前使用",
        "imported" => "已导入",
        "superseded" => "已替换",
        "revoked" => "已撤销",
        "import_failed" => "导入失败",
        _ => Status
    };

    public string ImportedAtDisplay => ImportedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
