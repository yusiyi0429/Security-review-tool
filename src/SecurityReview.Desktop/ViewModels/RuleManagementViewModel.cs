using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SecurityReview.Application.Rules;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Schema;
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

    private readonly Func<IRulePackPreviewProvider>? _previewProviderFactory;

    private IReadOnlyList<RuleEntryItem> _allRuleEntries = Array.Empty<RuleEntryItem>();
    private ObservableCollection<RuleEntryItem> _ruleEntries = new();
    private ObservableCollection<string> _categoryFilters = new();
    private string _ruleSearchText = "";
    private string? _selectedCategoryFilter;
    private RuleEntryItem? _selectedRuleEntry;
    private bool _hasSelectedRuleEntry;
    private bool _hasRuleEntries;
    private string _ruleEntriesStatus = "";
    private string _activeSourceBadge = "";

    public RuleManagementViewModel(
        Func<RulePackImportService> importFactory,
        IUiErrorSink errorSink,
        Func<IRulePackStore>? storeFactory = null,
        Func<Task>? configurationChanged = null,
        Func<IRulePackPreviewProvider>? previewProviderFactory = null)
    {
        _importFactory = importFactory;
        _storeFactory = storeFactory;
        _errorSink = errorSink;
        _configurationChanged = configurationChanged;
        _previewProviderFactory = previewProviderFactory;

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

    public ObservableCollection<RuleEntryItem> RuleEntries
    {
        get => _ruleEntries;
        private set => SetProperty(ref _ruleEntries, value);
    }

    public ObservableCollection<string> CategoryFilters
    {
        get => _categoryFilters;
        private set => SetProperty(ref _categoryFilters, value);
    }

    public string RuleSearchText
    {
        get => _ruleSearchText;
        set
        {
            if (SetProperty(ref _ruleSearchText, value))
                ApplyRuleFilters();
        }
    }

    public string? SelectedCategoryFilter
    {
        get => _selectedCategoryFilter;
        set
        {
            if (SetProperty(ref _selectedCategoryFilter, value))
                ApplyRuleFilters();
        }
    }

    public RuleEntryItem? SelectedRuleEntry
    {
        get => _selectedRuleEntry;
        set
        {
            if (SetProperty(ref _selectedRuleEntry, value))
                HasSelectedRuleEntry = value is not null;
        }
    }

    public bool HasSelectedRuleEntry
    {
        get => _hasSelectedRuleEntry;
        private set => SetProperty(ref _hasSelectedRuleEntry, value);
    }

    public bool HasRuleEntries
    {
        get => _hasRuleEntries;
        private set => SetProperty(ref _hasRuleEntries, value);
    }

    public string RuleEntriesStatus
    {
        get => _ruleEntriesStatus;
        private set => SetProperty(ref _ruleEntriesStatus, value);
    }

    public string ActiveSourceBadge
    {
        get => _activeSourceBadge;
        private set
        {
            if (SetProperty(ref _activeSourceBadge, value))
                OnPropertyChanged(nameof(HasActiveSourceBadge));
        }
    }

    public bool HasActiveSourceBadge => _activeSourceBadge.Length > 0;

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
                ClearRuleEntries("尚未激活规则包，规则条目为空。");
                ActiveSourceBadge = "";
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
            ActiveSourceBadge = await ResolveSourceBadgeAsync(active.Sha256);
            await LoadRuleEntriesAsync();
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

    private void ClearRuleEntries(string status)
    {
        _allRuleEntries = Array.Empty<RuleEntryItem>();
        RuleEntries = new ObservableCollection<RuleEntryItem>();
        CategoryFilters = new ObservableCollection<string>();
        SelectedRuleEntry = null;
        HasRuleEntries = false;
        RuleEntriesStatus = status;
    }

    private async Task<string> ResolveSourceBadgeAsync(string activeSha256)
    {
        if (_previewProviderFactory is null)
            return "未知";
        string? bundledHash = await _previewProviderFactory()
            .GetBundledBaselineSha256Async(CancellationToken.None);
        if (bundledHash is null)
            return "未知";
        return string.Equals(activeSha256, bundledHash, StringComparison.OrdinalIgnoreCase)
            ? "内置"
            : "导入";
    }

    private async Task LoadRuleEntriesAsync()
    {
        ClearRuleEntries("");

        if (_previewProviderFactory is null)
        {
            RuleEntriesStatus = "规则条目预览不可用。";
            return;
        }

        try
        {
            RulePackDocument? document = await _previewProviderFactory()
                .GetActiveRulesAsync(CancellationToken.None);
            if (document is null)
            {
                RuleEntriesStatus = "当前没有活动规则包，规则条目为空。";
                return;
            }

            _allRuleEntries = ProjectRuleEntries(document);
            var filters = new ObservableCollection<string> { "全部" };
            foreach (string name in _allRuleEntries
                .Select(e => e.CategoryName)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(n => n, StringComparer.Ordinal))
            {
                filters.Add(name);
            }
            CategoryFilters = filters;
            _selectedCategoryFilter = "全部";
            OnPropertyChanged(nameof(SelectedCategoryFilter));
            ApplyRuleFilters();
        }
        catch (Exception)
        {
            ClearRuleEntries("规则条目加载失败 — 活动规则包可能已损坏，请重新导入。");
            _errorSink.Report("rule_entries_load_failed", "加载规则条目失败。");
        }
    }

    private void ApplyRuleFilters()
    {
        IEnumerable<RuleEntryItem> filtered = _allRuleEntries;
        if (!string.IsNullOrWhiteSpace(_ruleSearchText))
        {
            string term = _ruleSearchText.Trim();
            filtered = filtered.Where(e =>
                e.RuleId.Contains(term, StringComparison.OrdinalIgnoreCase)
                || e.CategoryName.Contains(term, StringComparison.OrdinalIgnoreCase)
                || e.DetectorId.Contains(term, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrEmpty(_selectedCategoryFilter)
            && _selectedCategoryFilter != "全部")
        {
            filtered = filtered.Where(e =>
                e.CategoryName == _selectedCategoryFilter);
        }

        var items = filtered.ToList();
        RuleEntries = new ObservableCollection<RuleEntryItem>(items);
        HasRuleEntries = items.Count > 0;
        RuleEntriesStatus = items.Count > 0
            ? $"共 {items.Count} 条规则"
            : "没有匹配的规则条目。";
    }

    private static IReadOnlyList<RuleEntryItem> ProjectRuleEntries(
        RulePackDocument document)
    {
        var categories = document.Categories.ToDictionary(c => c.CategoryId, c => c);
        var detectorsByConfig = document.Detectors
            .GroupBy(d => (d.Id, d.ConfigId))
            .ToDictionary(g => g.Key, g => g.First());
        var assetNames = document.Assets.ToDictionary(a => a.AssetTypeId, a => a.Name);

        var items = new List<RuleEntryItem>(document.Rules.Count);
        foreach (RuleDefinition rule in document.Rules)
        {
            categories.TryGetValue(rule.CategoryId, out CategoryDefinition? category);
            if (!detectorsByConfig.TryGetValue(
                    (rule.DetectorId, rule.DetectorConfigId),
                    out DetectorDefinition? detector))
            {
                detector = document.Detectors
                    .FirstOrDefault(d => d.Id == rule.DetectorId);
            }

            string parameters = detector is null
                ? ""
                : string.Join('\n',
                    detector.Parameters.Select(p => $"{p.Key} = {p.Value}"));
            string appliesTo = rule.AppliesToAssets.Count == 0
                ? ""
                : string.Join(", ", rule.AppliesToAssets
                    .OrderBy(id => id.Value, StringComparer.Ordinal)
                    .Select(id => assetNames.TryGetValue(id, out string? name)
                        ? name
                        : id.Value));

            items.Add(new RuleEntryItem(
                rule.Id.Value,
                rule.CategoryId.Value,
                category?.Name ?? rule.CategoryId.Value,
                category?.Description ?? "",
                rule.FindingKind,
                rule.Severity,
                rule.Confidence,
                rule.DetectorId.Value,
                detector?.Kind.ToString() ?? "",
                parameters,
                appliesTo,
                rule.RequiresSemanticReview,
                rule.Enabled));
        }
        return items;
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

/// <summary>
/// Display item for a single rule entry of the active rule pack.
/// Rules carry no name/description, so the category and detector are
/// joined in for display.
/// </summary>
public sealed record RuleEntryItem(
    string RuleId,
    string CategoryId,
    string CategoryName,
    string CategoryDescription,
    FindingKind FindingKind,
    Severity Severity,
    DetectionConfidence Confidence,
    string DetectorId,
    string DetectorKind,
    string DetectorParameters,
    string AppliesToAssets,
    bool RequiresSemanticReview,
    bool Enabled)
{
    public string KindDisplay => FindingKind switch
    {
        FindingKind.SensitiveContent => "敏感内容",
        FindingKind.AssetCompliance => "资产合规",
        _ => FindingKind.ToString(),
    };

    public string SeverityDisplay => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高",
        Severity.Medium => "中",
        Severity.Low => "低",
        Severity.Info => "信息",
        _ => Severity.ToString(),
    };

    public string ConfidenceDisplay => Confidence switch
    {
        DetectionConfidence.High => "高",
        DetectionConfidence.Medium => "中",
        DetectionConfidence.Low => "低",
        _ => Confidence.ToString(),
    };

    public string EnabledDisplay => Enabled ? "启用" : "停用";
    public string SemanticReviewDisplay => RequiresSemanticReview ? "需要" : "不需要";
}
