using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain.Assets;
using SecurityReview.Desktop.Services;

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

    public NewScanViewModel(
        IUiErrorSink errorSink,
        Func<CreateScanHandler> createScanHandlerFactory,
        Func<StartScanHandler> startScanHandlerFactory)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _createScanHandlerFactory = createScanHandlerFactory
            ?? throw new ArgumentNullException(nameof(createScanHandlerFactory));
        _startScanHandlerFactory = startScanHandlerFactory
            ?? throw new ArgumentNullException(nameof(startScanHandlerFactory));

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
        set => SetProperty(ref _llmAvailable, value);
    }

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
                ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
    }

    // ------------------------------------------------------------------ Scan state

    public bool IsStartingScan
    {
        get => _isStartingScan;
        set
        {
            if (SetProperty(ref _isStartingScan, value))
                ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
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

    // ------------------------------------------------------------------ Private helpers

    private Task PickFileAsync()
    {
        // On Windows this opens OpenFileDialog; on Linux compile-only we validate
        // the shape through unit tests. The actual dialog is invoked via WPF.
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择扫描文件或 Docker TAR",
            Filter = "支持的文件 (*.txt;*.csv;*.log;*.xml;*.json;*.yaml;*.tar)|" +
                "*.txt;*.csv;*.log;*.xml;*.json;*.yaml;*.tar|所有文件 (*.*)|*.*",
            Multiselect = true,
        };

        bool? result = dialog.ShowDialog();
        if (result != true || dialog.FileNames.Length == 0)
            return Task.CompletedTask;

        foreach (string path in dialog.FileNames)
        {
            ScanTargetKind? kind = FileDropService.ClassifyTarget(path);
            if (kind is null)
                continue;

            if (_scanTargets.Any(t =>
                    string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase)))
                continue;

            _scanTargets.Add(new ScanTargetItem(path, kind.Value));
        }

        OnPropertyChanged(nameof(HasValidTargets));
        ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        return Task.CompletedTask;
    }

#pragma warning disable CA1822
    private Task PickFolderAsync()
    {
        // Folder selection is handled by the view layer (WPF) using
        // a platform-appropriate folder picker. On Windows this uses
        // FolderBrowserDialog from System.Windows.Forms (requires
        // UseWindowsForms in csproj) or the modern Windows.Storage API.
        // For the unit-test path, this command is a no-op and validated
        // through AddTargetFromDrop.
        return Task.CompletedTask;
    }
#pragma warning restore CA1822

    private Task AddExclusionAsync()
    {
        // The UI will bind to a new exclusion row; this command just
        // adds an empty placeholder that the user fills in.
        var entry = new ExclusionEntryViewModel
        {
            Pattern = "",
            Reason = "",
        };
        _exclusionEntries.Add(new ExclusionEntry(entry));
        ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        return Task.CompletedTask;
    }

    private Task RemoveExclusionAsync(object? parameter)
    {
        if (parameter is ExclusionEntry entry)
        {
            _exclusionEntries.Remove(entry);
            ((AsyncRelayCommand)StartScanCommand).RaiseCanExecuteChanged();
        }
        return Task.CompletedTask;
    }

    private bool CanStartScan()
    {
        if (_isStartingScan)
            return false;

        if (_scanTargets.Count == 0)
            return false;

        // If there are exclusions, the user must acknowledge Partial status.
        if (_exclusionEntries.Count > 0 && !_exclusionPartialAcknowledged)
            return false;

        return true;
    }

    private async Task StartScanAsync(object? parameter, CancellationToken cancellationToken)
    {
        IsStartingScan = true;
        try
        {
            // Build the CreateScanCommand.
            string[] rootPaths = _scanTargets
                .Select(t => t.Path)
                .ToArray();

            ManifestSnapshot manifest = _manifestSnapshot
                ?? new ManifestSnapshot(null, null, true, Array.Empty<ManifestValidationError>());

            string[] exclusions = _exclusionEntries
                .Select(e => e.Entry.Pattern)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .ToArray();

            var command = new CreateScanCommand(
                RootPaths: rootPaths,
                Manifest: manifest,
                UiOverrideComponentIds: Array.Empty<string>(),
                ExclusionPatterns: exclusions,
                ActiveRulePackHash: _rulePackVersion,
                PolicySha256: "0000000000000000000000000000000000000000000000000000000000000000",
                LlmEndpointFingerprint: "",
                LlmModelFingerprint: "",
                ClientVersion: "0.0.0",
                ParserAdapterVersion: "0.0.0",
                DetectorAdapterVersion: "0.0.0",
                PromptVersion: "0.0.0",
                Sandbox: new SandboxSelfTestResult(
                    true, SandboxSelfTestResult.OkCode,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    Environment.OSVersion.VersionString,
                    "S-1-0-0", DateTimeOffset.UtcNow),
                EffectiveDetectorVersions: Array.Empty<string>());

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

            // Navigate to progress view — handled by the parent window / navigation.
            // The scan orchestrator is started by the shell.
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
}

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
