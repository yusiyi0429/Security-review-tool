using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows.Input;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain.Assets;
using SecurityReview.Desktop.Services;
using SecurityReview.Domain.Llm;
using SecurityReview.Infrastructure.Llm;
using SecurityReview.Infrastructure.Rules;

namespace SecurityReview.Desktop.ViewModels;

/// <summary>
/// View model for the New Scan setup page. Handles file/folder selection,
/// drag-and-drop import, Manifest validation, asset/component mapping,
/// rule package status, LLM connection warnings, and user exclusions.
///
/// The Start command can only execute when at least one valid scan target
/// is present and the scanner is not already running.
/// </summary>
public sealed class NewScanViewModel : ObservableObject
{
    private readonly IUiErrorSink _errorSink;
    private readonly Func<CreateScanHandler> _createScanHandlerFactory;
    private readonly Func<StartScanHandler> _startScanHandlerFactory;
    private readonly IScanTargetPicker _targetPicker;
    private readonly ActiveRulePackRuntimeProvider? _rulePackRuntimeProvider;
    private readonly ILlmConfigurationStore? _llmConfigurationStore;
    private readonly ILlmCredentialStore? _llmCredentialStore;
    private readonly IManifestReader? _manifestReader;
    private readonly ISandboxSelfTest? _sandboxSelfTest;
    private readonly StartupHealthService? _startupHealth;

    // Collection of scan targets (paths).
    private readonly ObservableCollection<ScanTargetItem> _scanTargets = new();

    // Exclusion entries with reason.
    private readonly ObservableCollection<ExclusionEntry> _exclusionEntries = new();

    // Manifest state.
    private ManifestSnapshot? _manifestSnapshot;
    private string _manifestStatus = "";
    private bool _manifestValid;
    private string _manifestSummary = "";

    // Rule pack status.
    private string _rulePackStatus = "";
    private string _rulePackVersion = "";
    private string _activeRuleWarning = "";
    private bool _hasOldRuleWarning;

    // LLM state.
    private bool _llmAvailable;
    private string _llmWarning = "";

    // Exclusion Partial acknowledgement.
    private bool _exclusionPartialAcknowledged;

    // Scan in progress.
    private bool _isStartingScan;
    private bool _initialized;
    private ActiveRulePackRuntime? _activeRulePack;

    public NewScanViewModel(
        IUiErrorSink errorSink,
        Func<CreateScanHandler> createScanHandlerFactory,
        Func<StartScanHandler> startScanHandlerFactory,
        IScanTargetPicker? targetPicker = null,
        ActiveRulePackRuntimeProvider? rulePackRuntimeProvider = null,
        ISandboxSelfTest? sandboxSelfTest = null,
        StartupHealthService? startupHealth = null,
        ILlmConfigurationStore? llmConfigurationStore = null,
        IManifestReader? manifestReader = null,
        ILlmCredentialStore? llmCredentialStore = null)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _createScanHandlerFactory = createScanHandlerFactory
            ?? throw new ArgumentNullException(nameof(createScanHandlerFactory));
        _startScanHandlerFactory = startScanHandlerFactory
            ?? throw new ArgumentNullException(nameof(startScanHandlerFactory));
        _targetPicker = targetPicker ?? new WpfScanTargetPicker();
        _rulePackRuntimeProvider = rulePackRuntimeProvider;
        _llmConfigurationStore = llmConfigurationStore;
        _llmCredentialStore = llmCredentialStore;
        _manifestReader = manifestReader;
        _sandboxSelfTest = sandboxSelfTest;
        _startupHealth = startupHealth;
        if (_startupHealth is not null)
        {
            _startupHealth.PropertyChanged += OnStartupHealthChanged;
        }

        PickFileCommand = new AsyncRelayCommand(
            _ => PickFileAsync(), errorSink);
        PickFolderCommand = new AsyncRelayCommand(
            _ => PickFolderAsync(), errorSink);
        AddExclusionCommand = new AsyncRelayCommand(
            _ => AddExclusionAsync(), errorSink);
        RemoveExclusionCommand = new AsyncRelayCommand(
            RemoveExclusionAsync, errorSink);
        StartScanCommand = new AsyncRelayCommand(
            StartScanAsync, errorSink, _ => CanStartScan());
    }

    // ------------------------------------------------------------------ Commands

    public ICommand PickFileCommand { get; }
    public ICommand PickFolderCommand { get; }
    public ICommand AddExclusionCommand { get; }
    public ICommand RemoveExclusionCommand { get; }
    public ICommand StartScanCommand { get; }

    public event Func<ScanLaunchRequest, CancellationToken, Task>? ScanLaunchRequested;

    // ------------------------------------------------------------------ Scan targets

    public ObservableCollection<ScanTargetItem> ScanTargets => _scanTargets;

    /// <summary>Whether at least one valid scan target is present.</summary>
    public bool HasValidTargets => _scanTargets.Count > 0;

    // ------------------------------------------------------------------ Manifest

    public string ManifestStatus
    {
        get => _manifestStatus;
        set => SetProperty(ref _manifestStatus, value);
    }

    public bool ManifestValid
    {
        get => _manifestValid;
        set => SetProperty(ref _manifestValid, value);
    }

    public string ManifestSummary
    {
        get => _manifestSummary;
        set => SetProperty(ref _manifestSummary, value);
    }

    /// <summary>The resolved manifest snapshot for the first root.</summary>
    public ManifestSnapshot? CurrentManifest => _manifestSnapshot;

    // ------------------------------------------------------------------ Rule pack

    public string RulePackStatus
    {
        get => _rulePackStatus;
        set => SetProperty(ref _rulePackStatus, value);
    }

    public string RulePackVersion
    {
        get => _rulePackVersion;
        set => SetProperty(ref _rulePackVersion, value);
    }

    public string ActiveRuleWarning
    {
        get => _activeRuleWarning;
        set => SetProperty(ref _activeRuleWarning, value);
    }

    public bool HasOldRuleWarning
    {
        get => _hasOldRuleWarning;
        set => SetProperty(ref _hasOldRuleWarning, value);
    }

    // ------------------------------------------------------------------ LLM

    public bool LlmAvailable
    {
        get => _llmAvailable;
        set
        {
            if (SetProperty(ref _llmAvailable, value))
                OnPropertyChanged(nameof(LlmStatus));
        }
    }

    public string LlmStatus => LlmAvailable ? "已配置" : "未配置";

    public string LlmWarning
    {
        get => _llmWarning;
        set => SetProperty(ref _llmWarning, value);
    }

    // ------------------------------------------------------------------ Exclusions

    public ObservableCollection<ExclusionEntry> ExclusionEntries => _exclusionEntries;

    public bool ExclusionPartialAcknowledged
    {
        get => _exclusionPartialAcknowledged;
        set
        {
            if (SetProperty(ref _exclusionPartialAcknowledged, value))
            {
                ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(ScanReadinessMessage));
            }
        }
    }

    // ------------------------------------------------------------------ Scan state

    public bool IsStartingScan
    {
        get => _isStartingScan;
        set
        {
            if (SetProperty(ref _isStartingScan, value))
            {
                ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(StartButtonText));
                OnPropertyChanged(nameof(ScanReadinessMessage));
            }
        }
    }

    public string StartButtonText => IsStartingScan
        ? "正在启动安全扫描…"
        : "开始安全扫描  →";

    public string ScanReadinessMessage
    {
        get
        {
            if (_scanTargets.Count == 0)
                return "请先选择至少一个文件或目录。";

            if (_rulePackRuntimeProvider is not null && _activeRulePack is null)
                return "请先在「规则管理」中导入并激活有效的签名规则包。";

            if (_startupHealth?.State == StartupHealthState.Checking)
                return "正在检查安全解析环境，请稍候。";

            if (_startupHealth?.State == StartupHealthState.Blocked)
                return $"安全解析环境不可用（{_startupHealth.BlockedCode}），请查看诊断信息。";

            if (_exclusionEntries.Count > 0 && !_exclusionPartialAcknowledged)
                return "存在排除项，请先确认其对扫描完整性的影响。";

            if (_exclusionEntries.Any(entry => !entry.Entry.IsValid))
                return "每个排除项都必须填写匹配模式和原因。";

            return "";
        }
    }

    // ------------------------------------------------------------------ Public methods

    /// <summary>
    /// Adds a validated path from drag-and-drop. Validates the path and
    /// classifies the target kind. Duplicates are silently ignored.
    /// </summary>
    public void AddTargetFromDrop(string path)
    {
        ScanTargetKind? kind = FileDropService.ClassifyTarget(path);
        if (kind is null)
            return;

        // Check for duplicates
        if (_scanTargets.Any(t =>
                string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase)))
            return;

        _scanTargets.Add(new ScanTargetItem(path, kind.Value));
        OnPropertyChanged(nameof(HasValidTargets));
        OnPropertyChanged(nameof(ScanReadinessMessage));
        ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
    }

    /// <summary>
    /// Applies the manifest read result for a root path and updates the UI.
    /// </summary>
    public void ApplyManifest(ManifestReadResult result)
    {
        _manifestSnapshot = result.Snapshot;

        if (result.Snapshot is null)
        {
            ManifestStatus = "清单未找到";
            ManifestValid = false;
            ManifestSummary = "此扫描根目录未包含资产清单 (asset-manifest.json)。将使用基线映射。";
        }
        else if (result.Invalid)
        {
            ManifestStatus = "清单无效";
            ManifestValid = false;
            int errorCount = result.Snapshot.Errors.Count;
            ManifestSummary = $"清单包含 {errorCount} 个验证错误。将使用基线映射。";
        }
        else
        {
            ManifestStatus = "清单有效";
            ManifestValid = true;
            AssetManifest? manifest = result.Snapshot.Manifest;
            if (manifest is not null)
            {
                ManifestSummary = $"资产: {manifest.AssetId} v{manifest.AssetVersion}, " +
                    $"{manifest.Components.Count} 个组件映射";
            }
            else
            {
                ManifestSummary = "清单已解析但未包含资产定义。将使用基线映射。";
            }
        }
    }

    /// <summary>
    /// Applies the current rule pack state to the view model.
    /// </summary>
    public void ApplyRulePackState(string rulePackVersion, bool isLatest)
    {
        RulePackVersion = rulePackVersion;
        RulePackStatus = isLatest ? "当前" : "非最新";
        HasOldRuleWarning = !isLatest;
        ActiveRuleWarning = isLatest
            ? ""
            : "当前规则包非最新版本。建议导入最新规则包后重新扫描。";
    }

    /// <summary>
    /// Applies the LLM connection state.
    /// </summary>
    public void ApplyLlmState(bool available, string warning)
    {
        LlmAvailable = available;
        LlmWarning = warning;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized
            && _rulePackRuntimeProvider is null
            && _llmConfigurationStore is null)
        {
            return;
        }

        _initialized = true;
        if (_rulePackRuntimeProvider is not null)
        {
            await LoadActiveRulePackAsync(cancellationToken).ConfigureAwait(true);
        }

        if (_llmConfigurationStore is not null)
        {
            await LoadLlmStateAsync(cancellationToken).ConfigureAwait(true);
        }
    }

    private async Task LoadActiveRulePackAsync(CancellationToken cancellationToken)
    {
        try
        {
            _activeRulePack = await _rulePackRuntimeProvider!
                .GetActiveAsync(cancellationToken)
                .ConfigureAwait(true);
            if (_activeRulePack is null)
            {
                RulePackVersion = "未配置";
                RulePackStatus = "不可用";
                HasOldRuleWarning = true;
                ActiveRuleWarning = "尚未导入并激活签名规则包，请先前往「规则管理」。";
            }
            else
            {
                ApplyRulePackState(_activeRulePack.Active.Version, isLatest: true);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException
            or JsonException or UnauthorizedAccessException or InvalidOperationException)
        {
            _activeRulePack = null;
            RulePackVersion = "加载失败";
            RulePackStatus = "不可用";
            HasOldRuleWarning = true;
            ActiveRuleWarning = "激活规则包无法加载或完整性校验失败。";
            _errorSink.Report(
                "rule_pack_load_failed",
                "激活规则包无法加载，请重新导入有效的签名规则包。");
        }
        finally
        {
            OnPropertyChanged(nameof(ScanReadinessMessage));
            ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
    }

    private async Task LoadLlmStateAsync(CancellationToken cancellationToken)
    {
        try
        {
            var options = await _llmConfigurationStore!
                .LoadAsync(cancellationToken)
                .ConfigureAwait(true);
            bool credentialReady = options is not null
                && (options.AuthMode == LlmAuthMode.None
                    || options.CredentialReference is { Length: > 0 } reference
                    && _llmCredentialStore?.HasCredential(reference) == true);
            ApplyLlmState(
                options is not null && credentialReady,
                options is null
                    ? "LLM 未配置；核心规则扫描仍可独立运行。"
                    : credentialReady
                        ? ""
                        : "LLM 配置存在，但凭据缺失；核心规则扫描仍可独立运行。");
        }
        catch (Exception)
        {
            ApplyLlmState(
                available: false,
                "LLM 配置加载失败；核心规则扫描仍可独立运行。");
            _errorSink.Report(
                "llm_config_load_failed",
                "加载 LLM 配置失败，请前往「LLM 设置」检查配置。");
        }
    }

    // ------------------------------------------------------------------ Private helpers

    private Task PickFileAsync()
    {
        AddPickedTargets(_targetPicker.PickFiles());
        return Task.CompletedTask;
    }

    private Task PickFolderAsync()
    {
        AddPickedTargets(_targetPicker.PickFolders());
        return Task.CompletedTask;
    }

    private void AddPickedTargets(IEnumerable<string> paths)
    {
        foreach (string path in paths)
        {
            AddTargetFromDrop(path);
        }
    }

    private Task AddExclusionAsync()
    {
        // The UI will bind to a new exclusion row; this command just
        // adds an empty placeholder that the user fills in.
        var entry = new ExclusionEntryViewModel
        {
            Pattern = "",
            Reason = "",
        };
        entry.PropertyChanged += OnExclusionEntryChanged;
        _exclusionEntries.Add(new ExclusionEntry(entry));
        OnPropertyChanged(nameof(ScanReadinessMessage));
        ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        return Task.CompletedTask;
    }

    private Task RemoveExclusionAsync(object? parameter)
    {
        if (parameter is ExclusionEntry entry)
        {
            entry.Entry.PropertyChanged -= OnExclusionEntryChanged;
            _exclusionEntries.Remove(entry);
            OnPropertyChanged(nameof(ScanReadinessMessage));
            ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
        return Task.CompletedTask;
    }

    private void OnExclusionEntryChanged(
        object? sender,
        PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ExclusionEntryViewModel.Pattern)
            or nameof(ExclusionEntryViewModel.Reason))
        {
            OnPropertyChanged(nameof(ScanReadinessMessage));
            ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
    }

    private bool CanStartScan()
    {
        if (_isStartingScan)
            return false;

        if (_scanTargets.Count == 0)
            return false;

        if (_rulePackRuntimeProvider is not null && _activeRulePack is null)
            return false;

        if (_startupHealth is not null && !_startupHealth.CanStartScan)
            return false;

        // If there are exclusions, the user must acknowledge Partial status.
        if (_exclusionEntries.Count > 0 && !_exclusionPartialAcknowledged)
            return false;

        if (_exclusionEntries.Any(entry => !entry.Entry.IsValid))
            return false;

        return true;
    }

    private async Task StartScanAsync(object? parameter, CancellationToken cancellationToken)
    {
        IsStartingScan = true;
        try
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(true);
            if (_rulePackRuntimeProvider is not null && _activeRulePack is null)
            {
                _errorSink.Report(
                    "baseline_inactive",
                    "请先在「规则管理」中导入并激活有效的签名规则包。");
                return;
            }

            SandboxSelfTestResult sandboxResult = _sandboxSelfTest is null
                ? new SandboxSelfTestResult(
                    true,
                    SandboxSelfTestResult.OkCode,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    Environment.OSVersion.VersionString,
                    "S-1-0-0",
                    DateTimeOffset.UtcNow)
                : await _sandboxSelfTest
                    .RunAsync(cancellationToken)
                    .ConfigureAwait(true);
            if (!sandboxResult.Passed)
            {
                _startupHealth?.MarkBlocked(sandboxResult.Code);
                _errorSink.Report(
                    "sandbox_unavailable",
                    $"安全解析沙箱不可用（{sandboxResult.Code}），扫描未启动。");
                return;
            }

            // Build the CreateScanCommand.
            string[] rootPaths = _scanTargets
                .Select(t => t.Path)
                .ToArray();

            ManifestSnapshot[] rootManifests = await CaptureRootManifestsAsync(
                    rootPaths, cancellationToken)
                .ConfigureAwait(true);
            if (rootManifests.Any(manifest => !manifest.Valid))
            {
                _errorSink.Report(
                    "manifest_invalid",
                    "至少一个扫描根目录包含无效资产清单；请修复后重试。");
                return;
            }

            ManifestSnapshot manifest = rootManifests.FirstOrDefault()
                ?? new ManifestSnapshot(
                    null, null, true, Array.Empty<ManifestValidationError>());

            string[] exclusions = _exclusionEntries
                .Select(e => e.Entry.Pattern)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToArray();
            ScanExclusion[] exclusionRecords = _exclusionEntries
                .Select(entry => new ScanExclusion(
                    entry.Entry.Pattern.Trim(),
                    entry.Entry.Reason.Trim()))
                .ToArray();
            LlmEndpointOptions? llmOptions = _llmConfigurationStore is null
                ? null
                : await _llmConfigurationStore
                    .LoadAsync(cancellationToken)
                    .ConfigureAwait(true);

            var command = new CreateScanCommand(
                RootPaths: rootPaths,
                Manifest: manifest,
                UiOverrideComponentIds: Array.Empty<string>(),
                ExclusionPatterns: exclusions,
                ActiveRulePackHash: _activeRulePack?.Active.Sha256
                    ?? _rulePackVersion,
                PolicySha256: _activeRulePack?.Package.Policy.PolicySha256
                    ?? "0000000000000000000000000000000000000000000000000000000000000000",
                LlmEndpointFingerprint: llmOptions?.OriginFingerprint()
                    ?? string.Empty,
                LlmModelFingerprint: llmOptions is null
                    ? string.Empty
                    : OpenAiSemanticReviewer.ComputeModelFingerprint(
                        llmOptions.Model),
                ClientVersion: typeof(NewScanViewModel).Assembly
                    .GetName().Version?.ToString(3) ?? "0.0.0",
                ParserAdapterVersion: "1.0.0",
                DetectorAdapterVersion: "1.0.0",
                PromptVersion: "1.0.0",
                Sandbox: sandboxResult,
                EffectiveDetectorVersions: _activeRulePack?.Package.Policy
                    .ActiveDetectorVersions
                    .Select(pair => $"{pair.Key}:{pair.Value}")
                    .ToArray()
                    ?? Array.Empty<string>(),
                RootManifests: rootManifests,
                Exclusions: exclusionRecords);

            // Create the scan (Draft).
            CreateScanHandler createHandler = _createScanHandlerFactory();
            CreateScanResult createResult = await createHandler
                .HandleAsync(command, cancellationToken)
                .ConfigureAwait(true);

            if (!createResult.Created)
            {
                string error = createResult.Errors.Count > 0
                    ? createResult.Errors[0].Message
                    : "扫描创建失败。";
                _errorSink.Report("scan_create_failed", error);
                return;
            }

            // Start the scan (transition to Preflight).
            StartScanHandler startHandler = _startScanHandlerFactory();
            StartScanResult startResult = await startHandler
                .HandleAsync(createResult.ScanId!.Value, cancellationToken)
                .ConfigureAwait(true);

            if (!startResult.Started)
            {
                string error = startResult.Errors.Count > 0
                    ? startResult.Errors[0].Message
                    : "扫描启动失败。";
                _errorSink.Report("scan_start_failed", error);
                return;
            }

            if (ScanLaunchRequested is null
                || startResult.ScanId is null
                || startResult.Snapshot is null)
            {
                _errorSink.Report(
                    "scan_execution_unavailable",
                    "扫描执行服务未连接，请重新启动应用后重试。");
                return;
            }

            await ScanLaunchRequested(
                    new ScanLaunchRequest(
                        startResult.ScanId.Value,
                        startResult.Snapshot),
                    cancellationToken)
                .ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            // Cancellation is expected.
        }
        catch (Exception ex)
        {
            string message = AsyncRelayCommand.SanitizeMessage(ex);
            _errorSink.Report("scan_start_error", message);
        }
        finally
        {
            IsStartingScan = false;
        }
    }

    private async Task<ManifestSnapshot[]> CaptureRootManifestsAsync(
        string[] rootPaths,
        CancellationToken cancellationToken)
    {
        if (_manifestReader is null)
        {
            return rootPaths
                .Select((_, index) => index == 0 && _manifestSnapshot is not null
                    ? _manifestSnapshot
                    : new ManifestSnapshot(
                        null, null, true,
                        Array.Empty<ManifestValidationError>()))
                .ToArray();
        }

        var snapshots = new ManifestSnapshot[rootPaths.Length];
        for (int index = 0; index < rootPaths.Length; index++)
        {
            string fullPath = Path.GetFullPath(rootPaths[index]);
            string root = File.Exists(fullPath)
                ? Path.GetDirectoryName(fullPath)
                    ?? throw new InvalidOperationException(
                        "扫描文件没有可用的父目录。")
                : fullPath;
            ManifestReadResult result = await _manifestReader
                .ReadAsync(root, cancellationToken)
                .ConfigureAwait(true);
            snapshots[index] = result.Snapshot
                ?? new ManifestSnapshot(
                    null, null, true,
                    Array.Empty<ManifestValidationError>());
            if (index == 0)
            {
                ApplyManifest(result);
            }
        }

        return snapshots;
    }

    private void OnStartupHealthChanged(
        object? sender,
        PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(StartupHealthService.CanStartScan)
            or nameof(StartupHealthService.State))
        {
            OnPropertyChanged(nameof(ScanReadinessMessage));
            ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
    }
}

public sealed record ScanLaunchRequest(
    Domain.ScanId ScanId,
    ScanConfigurationSnapshot Snapshot);

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// <summary>
/// A single scan target with its path and classified kind.
/// </summary>
public sealed record ScanTargetItem(string Path, ScanTargetKind Kind)
{
    public string DisplayName
    {
        get
        {
            // Elide sensitive middle path segments for display.
            string fileName = System.IO.Path.GetFileName(Path);
            string? directory = System.IO.Path.GetDirectoryName(Path);
            if (string.IsNullOrEmpty(directory))
                return fileName;

            string root = System.IO.Path.GetPathRoot(Path) ?? "";
            if (directory.Length <= root.Length + 20)
                return Path;

            // Show root + ... + filename
            return $"{root}...{System.IO.Path.DirectorySeparatorChar}{fileName}";
        }
    }

    public string KindDisplay => Kind switch
    {
        ScanTargetKind.File => "文件",
        ScanTargetKind.Directory => "目录",
        ScanTargetKind.DockerTar => "Docker TAR",
        ScanTargetKind.OciDirectory => "OCI 布局",
        _ => "未知",
    };
}

/// <summary>
/// An exclusion entry with pattern and mandatory reason.
/// </summary>
public sealed record ExclusionEntry(ExclusionEntryViewModel Entry);

/// <summary>
/// Mutable view model for a single exclusion pattern row.
/// </summary>
public sealed class ExclusionEntryViewModel : ObservableObject
{
    private string _pattern = "";
    private string _reason = "";

    public string Pattern
    {
        get => _pattern;
        set => SetProperty(ref _pattern, value);
    }

    public string Reason
    {
        get => _reason;
        set => SetProperty(ref _reason, value);
    }

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(_pattern) && !string.IsNullOrWhiteSpace(_reason);
}
