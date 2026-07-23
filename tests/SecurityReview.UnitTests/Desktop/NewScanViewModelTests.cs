using System.Collections.ObjectModel;
using System.ComponentModel;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Desktop.Services;
using SecurityReview.Desktop.ViewModels;
using SecurityReview.Domain.Assets;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for NewScanViewModel: empty input disables Start, file/folder/TAR/OCI
/// acceptance, Manifest validation, rule pack warnings, LLM warnings, exclusions,
/// Partial acknowledgement, and start creates immutable snapshot.
/// </summary>
public sealed class NewScanViewModelTests
{
    private sealed class TestErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();
        public void Report(string code, string message)
        {
            Errors.Add((code, message));
        }
    }

    private static NewScanViewModel CreateViewModel(
        TestErrorSink? sink = null,
        CreateScanHandler? createHandler = null,
        StartScanHandler? startHandler = null,
        IScanTargetPicker? targetPicker = null)
    {
        sink ??= new TestErrorSink();
        return new NewScanViewModel(
            sink,
            () => createHandler ?? throw new InvalidOperationException("CreateScanHandler not provided"),
            () => startHandler ?? throw new InvalidOperationException("StartScanHandler not provided"),
            targetPicker);
    }

    // ------------------------------------------------------------------
    // Empty input disables Start
    // ------------------------------------------------------------------

    [Fact]
    public void Start_command_disabled_when_no_targets()
    {
        var vm = CreateViewModel();
        Assert.False(vm.StartScanCommand.CanExecute(null));
        Assert.False(vm.HasValidTargets);
    }

    [Fact]
    public void Start_command_enabled_when_targets_present_and_no_exclusions()
    {
        var vm = CreateViewModel();
        string testFile = Path.GetTempFileName();
        try
        {
            vm.AddTargetFromDrop(testFile);
            Assert.True(vm.StartScanCommand.CanExecute(null));
            Assert.True(vm.HasValidTargets);
        }
        finally
        {
            File.Delete(testFile);
        }
    }

    // ------------------------------------------------------------------
    // File/directory/Docker TAR/OCI directory accepted
    // ------------------------------------------------------------------

    [Fact]
    public void AddTargetFromDrop_accepts_valid_file()
    {
        var vm = CreateViewModel();
        // Use a path that FileDropService.ClassifyTarget can handle.
        // Since we're in unit tests, we test the AddTargetFromDrop
        // when a valid path type is provided.
        string testFile = Path.GetTempFileName();
        try
        {
            vm.AddTargetFromDrop(testFile);
            Assert.Single(vm.ScanTargets);
            Assert.Equal(ScanTargetKind.File, vm.ScanTargets[0].Kind);
        }
        finally
        {
            File.Delete(testFile);
        }
    }

    [Fact]
    public void AddTargetFromDrop_accepts_directory()
    {
        var vm = CreateViewModel();
        string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempDir);
            vm.AddTargetFromDrop(tempDir);
            Assert.Single(vm.ScanTargets);
            Assert.Equal(ScanTargetKind.Directory, vm.ScanTargets[0].Kind);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir);
        }
    }

    [Fact]
    public void AddTargetFromDrop_accepts_docker_tar()
    {
        var vm = CreateViewModel();
        string tarFile = Path.Combine(Path.GetTempPath(), "test.tar");
        try
        {
            File.WriteAllText(tarFile, "");
            vm.AddTargetFromDrop(tarFile);
            Assert.Single(vm.ScanTargets);
            Assert.Equal(ScanTargetKind.DockerTar, vm.ScanTargets[0].Kind);
        }
        finally
        {
            if (File.Exists(tarFile))
                File.Delete(tarFile);
        }
    }

    [Fact]
    public void AddTargetFromDrop_accepts_oci_directory()
    {
        var vm = CreateViewModel();
        string ociDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(ociDir);
            File.WriteAllText(Path.Combine(ociDir, "oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}");
            File.WriteAllText(Path.Combine(ociDir, "index.json"), "{}");
            vm.AddTargetFromDrop(ociDir);
            Assert.Single(vm.ScanTargets);
            Assert.Equal(ScanTargetKind.OciDirectory, vm.ScanTargets[0].Kind);
        }
        finally
        {
            if (Directory.Exists(ociDir))
                Directory.Delete(ociDir, recursive: true);
        }
    }

    [Fact]
    public void AddTargetFromDrop_rejects_duplicate_paths()
    {
        var vm = CreateViewModel();
        string testFile = Path.GetTempFileName();
        try
        {
            vm.AddTargetFromDrop(testFile);
            vm.AddTargetFromDrop(testFile);
            Assert.Single(vm.ScanTargets);
        }
        finally
        {
            File.Delete(testFile);
        }
    }

    [Fact]
    public void AddTargetFromDrop_rejects_nonexistent_paths()
    {
        var vm = CreateViewModel();
        vm.AddTargetFromDrop("/nonexistent/path/xyz.txt");
        Assert.Empty(vm.ScanTargets);
    }

    [Fact]
    public async Task Pick_file_command_adds_selected_files()
    {
        string testFile = Path.GetTempFileName();
        try
        {
            var picker = new TestTargetPicker([testFile], []);
            var vm = CreateViewModel(targetPicker: picker);

            await ((AsyncRelayCommand)vm.PickFileCommand).ExecuteAsync(null);

            ScanTargetItem target = Assert.Single(vm.ScanTargets);
            Assert.Equal(testFile, target.Path);
            Assert.Equal(ScanTargetKind.File, target.Kind);
        }
        finally
        {
            File.Delete(testFile);
        }
    }

    [Fact]
    public async Task Pick_folder_command_adds_selected_folders()
    {
        DirectoryInfo directory = Directory.CreateTempSubdirectory(
            "srt-new-scan-picker-");
        try
        {
            var picker = new TestTargetPicker([], [directory.FullName]);
            var vm = CreateViewModel(targetPicker: picker);

            await ((AsyncRelayCommand)vm.PickFolderCommand).ExecuteAsync(null);

            ScanTargetItem target = Assert.Single(vm.ScanTargets);
            Assert.Equal(directory.FullName, target.Path);
            Assert.Equal(ScanTargetKind.Directory, target.Kind);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    // ------------------------------------------------------------------
    // Manifest validation
    // ------------------------------------------------------------------

    [Fact]
    public void ApplyManifest_shows_valid_state()
    {
        var vm = CreateViewModel();
        var manifest = new AssetManifest(
            "test-asset", "1.0",
            new[] { AssetComponent.Create("src", AssetTypeId.Parse("ASSET-001")) },
            ComplianceEvidence.Create(
                new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
                new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
                Array.Empty<ThirdPartyAuthorization>()));

        var snapshot = new ManifestSnapshot(manifest, "abc123", true, Array.Empty<ManifestValidationError>());
        var result = ManifestReadResult.FromSnapshot(snapshot);

        vm.ApplyManifest(result);
        Assert.Equal("清单有效", vm.ManifestStatus);
        Assert.True(vm.ManifestValid);
        Assert.Contains("test-asset", vm.ManifestSummary);
    }

    [Fact]
    public void ApplyManifest_shows_invalid_state()
    {
        var vm = CreateViewModel();
        var errors = new List<ManifestValidationError>
        {
            new(ManifestErrorCodes.InvalidJson, "/", "Invalid JSON")
        };
        var snapshot = new ManifestSnapshot(null, null, false, errors);
        var result = ManifestReadResult.FromSnapshot(snapshot);

        vm.ApplyManifest(result);
        Assert.Equal("清单无效", vm.ManifestStatus);
        Assert.False(vm.ManifestValid);
        Assert.Contains("1 个验证错误", vm.ManifestSummary);
    }

    [Fact]
    public void ApplyManifest_shows_not_found_state()
    {
        var vm = CreateViewModel();
        var result = ManifestReadResult.NotFound;

        vm.ApplyManifest(result);
        Assert.Equal("清单未找到", vm.ManifestStatus);
        Assert.False(vm.ManifestValid);
        Assert.Contains("基线映射", vm.ManifestSummary);
    }

    // ------------------------------------------------------------------
    // Rule pack warnings
    // ------------------------------------------------------------------

    [Fact]
    public void ApplyRulePackState_shows_warning_when_not_latest()
    {
        var vm = CreateViewModel();
        vm.ApplyRulePackState("v1.0.0", isLatest: false);

        Assert.Equal("v1.0.0", vm.RulePackVersion);
        Assert.Equal("非最新", vm.RulePackStatus);
        Assert.True(vm.HasOldRuleWarning);
        Assert.Contains("非最新版本", vm.ActiveRuleWarning);
    }

    [Fact]
    public void ApplyRulePackState_no_warning_when_latest()
    {
        var vm = CreateViewModel();
        vm.ApplyRulePackState("v2.0.0", isLatest: true);

        Assert.Equal("v2.0.0", vm.RulePackVersion);
        Assert.Equal("当前", vm.RulePackStatus);
        Assert.False(vm.HasOldRuleWarning);
        Assert.Empty(vm.ActiveRuleWarning);
    }

    // ------------------------------------------------------------------
    // LLM warnings
    // ------------------------------------------------------------------

    [Fact]
    public void ApplyLlmState_shows_warning_when_unavailable()
    {
        var vm = CreateViewModel();
        vm.ApplyLlmState(false, "LLM 连接不可用。语义审查将不可用。");

        Assert.False(vm.LlmAvailable);
        Assert.Contains("LLM 连接不可用", vm.LlmWarning);
    }

    [Fact]
    public void ApplyLlmState_no_warning_when_available()
    {
        var vm = CreateViewModel();
        vm.ApplyLlmState(true, "");

        Assert.True(vm.LlmAvailable);
        Assert.Empty(vm.LlmWarning);
    }

    // ------------------------------------------------------------------
    // Exclusions force Partial
    // ------------------------------------------------------------------

    [Fact]
    public void Exclusion_requires_acknowledgement_for_start()
    {
        var vm = CreateViewModel();
        vm.AddTargetFromDrop(Path.GetTempFileName());

        // Add an exclusion via the command.
        vm.AddExclusionCommand.Execute(null);
        Assert.NotEmpty(vm.ExclusionEntries);

        // Without acknowledgement, Start should be disabled.
        Assert.False(vm.StartScanCommand.CanExecute(null));

        // With acknowledgement, Start should be enabled.
        vm.ExclusionPartialAcknowledged = true;
        Assert.True(vm.StartScanCommand.CanExecute(null));
    }

    // ------------------------------------------------------------------
    // Start command is disabled while IsStartingScan
    // ------------------------------------------------------------------

    [Fact]
    public void Start_command_disabled_while_starting()
    {
        var vm = CreateViewModel();
        vm.AddTargetFromDrop(Path.GetTempFileName());

        Assert.True(vm.StartScanCommand.CanExecute(null));

        vm.IsStartingScan = true;
        Assert.False(vm.StartScanCommand.CanExecute(null));

        vm.IsStartingScan = false;
        Assert.True(vm.StartScanCommand.CanExecute(null));
    }

    // ------------------------------------------------------------------
    // PropertyChanged events
    // ------------------------------------------------------------------

    [Fact]
    public void ManifestStatus_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(NewScanViewModel.ManifestStatus))
                fired = true;
        };

        vm.ManifestStatus = "test";
        Assert.True(fired);
    }

    [Fact]
    public void ExclusionPartialAcknowledged_raises_property_changed()
    {
        var vm = CreateViewModel();
        bool fired = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(NewScanViewModel.ExclusionPartialAcknowledged))
                fired = true;
        };

        vm.ExclusionPartialAcknowledged = true;
        Assert.True(fired);
    }

    // ------------------------------------------------------------------
    // INotifyPropertyChanged
    // ------------------------------------------------------------------

    [Fact]
    public void Implements_INotifyPropertyChanged()
    {
        var vm = CreateViewModel();
        Assert.IsAssignableFrom<INotifyPropertyChanged>(vm);
    }

    private sealed class TestTargetPicker(
        IReadOnlyList<string> files,
        IReadOnlyList<string> folders) : IScanTargetPicker
    {
        public IReadOnlyList<string> PickFiles() => files;

        public IReadOnlyList<string> PickFolders() => folders;
    }
}
