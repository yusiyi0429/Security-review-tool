using System.Diagnostics;
using System.Security.Cryptography;
using SecurityReview.Application.Updates;
using SecurityReview.Desktop.Services;

namespace SecurityReview.UnitTests.Desktop;

/// <summary>
/// Tests for <see cref="UpdateApplier"/>: the pure bootstrapper content
/// builder, the fail-closed re-verification gate, and the apply flow's
/// process/shutdown seams (no real process is ever started, no real
/// shutdown happens).
/// </summary>
public sealed class UpdateApplierTests : IDisposable
{
    private static readonly byte[] InstallerBytes = "fake installer payload"u8.ToArray();

    private readonly List<string> _tempDirectories = new();

    public void Dispose()
    {
        foreach (string directory in _tempDirectories)
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }
    }

    // ------------------------------------------------------------------
    // BuildBootstrapperContent (pure function)
    // ------------------------------------------------------------------

    [Fact]
    public void build_bootstrapper_content_runs_installer_silently_without_restart()
    {
        string content = UpdateApplier.BuildBootstrapperContent();

        Assert.Contains($"\"%{UpdateApplier.InstallerPathVariable}%\" /VERYSILENT /NORESTART", content, StringComparison.Ordinal);
    }

    [Fact]
    public void build_bootstrapper_content_restarts_application_with_empty_title_and_quoted_path()
    {
        string content = UpdateApplier.BuildBootstrapperContent();

        Assert.Contains($"start \"\" \"%{UpdateApplier.ExePathVariable}%\"", content, StringComparison.Ordinal);
    }

    [Fact]
    public void build_bootstrapper_content_is_pure_ascii_and_crlf_terminated()
    {
        string content = UpdateApplier.BuildBootstrapperContent();

        // cmd parses batch files in the system codepage; the content must
        // never carry non-ASCII bytes (paths travel via environment variables).
        Assert.True(content.All(c => c <= 0x7F));
        Assert.EndsWith("\r\n", content, StringComparison.Ordinal);
        Assert.DoesNotContain("\n\n", content, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // VerifyInstaller (fail-closed gate)
    // ------------------------------------------------------------------

    [Fact]
    public void verify_installer_returns_true_when_hash_matches()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, HashOfInstaller());

        Assert.True(UpdateApplier.VerifyInstaller(download));
    }

    [Fact]
    public void verify_installer_accepts_uppercase_expected_hash()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, HashOfInstaller().ToUpperInvariant());

        Assert.True(UpdateApplier.VerifyInstaller(download));
    }

    [Fact]
    public void verify_installer_returns_false_when_hash_mismatches()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, new string('0', 64));

        Assert.False(UpdateApplier.VerifyInstaller(download));
    }

    [Fact]
    public void verify_installer_returns_false_when_file_is_missing()
    {
        string installerPath = Path.Combine(CreateTempDirectory(), "missing-setup.exe");
        var download = new AppDownloadResult(installerPath, HashOfInstaller());

        Assert.False(UpdateApplier.VerifyInstaller(download));
    }

    // ------------------------------------------------------------------
    // ApplyAndRestart
    // ------------------------------------------------------------------

    [Fact]
    public async Task apply_and_restart_reports_and_returns_without_starting_process_when_hash_mismatches()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, new string('0', 64));
        var sink = new RecordingErrorSink();
        var startCount = 0;
        var shutdownCount = 0;
        var applier = new UpdateApplier(
            sink,
            startProcess: _ => { startCount++; return true; },
            shutdown: () => shutdownCount++);

        bool applied = await applier.ApplyAndRestart(download);

        Assert.False(applied);
        Assert.True(sink.ContainsCode(UpdateApplier.VerificationFailedCode));
        Assert.Equal(0, startCount);
        Assert.Equal(0, shutdownCount);
    }

    [Fact]
    public async Task apply_and_restart_reports_and_returns_without_starting_process_when_file_is_missing()
    {
        string installerPath = Path.Combine(CreateTempDirectory(), "missing-setup.exe");
        var download = new AppDownloadResult(installerPath, HashOfInstaller());
        var sink = new RecordingErrorSink();
        var startCount = 0;
        var shutdownCount = 0;
        var applier = new UpdateApplier(
            sink,
            startProcess: _ => { startCount++; return true; },
            shutdown: () => shutdownCount++);

        bool applied = await applier.ApplyAndRestart(download);

        Assert.False(applied);
        Assert.True(sink.ContainsCode(UpdateApplier.VerificationFailedCode));
        Assert.Equal(0, startCount);
        Assert.Equal(0, shutdownCount);
    }

    [Fact]
    public async Task apply_and_restart_error_messages_do_not_leak_path_or_hash()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, new string('0', 64));
        var sink = new RecordingErrorSink();
        var applier = new UpdateApplier(sink, startProcess: _ => true, shutdown: () => { });

        bool applied = await applier.ApplyAndRestart(download);

        Assert.False(applied);
        var error = Assert.Single(sink.Errors);
        Assert.DoesNotContain(installerPath, error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(download.VerifiedSha256, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task apply_and_restart_starts_detached_cmd_bootstrapper_and_shuts_down_when_verified()
    {
        // Temp directory with spaces and non-ASCII characters: proves paths
        // survive via the process environment without any quoting/escaping.
        string installDirectory = CreateTempDirectory("更新 test dir ");
        string installerPath = Path.Combine(installDirectory, "setup.exe");
        File.WriteAllBytes(installerPath, InstallerBytes);
        var download = new AppDownloadResult(installerPath, HashOfInstaller());
        var sink = new RecordingErrorSink();
        ProcessStartInfo? started = null;
        var shutdownCount = 0;
        var applier = new UpdateApplier(
            sink,
            startProcess: info => { started = info; return true; },
            shutdown: () => shutdownCount++);

        bool applied = await applier.ApplyAndRestart(download);

        Assert.True(applied);
        Assert.Empty(sink.Errors);
        Assert.Equal(1, shutdownCount);

        Assert.NotNull(started);
        Assert.Equal("cmd.exe", started!.FileName);
        Assert.False(started.UseShellExecute);
        Assert.True(started.CreateNoWindow);
        Assert.Equal(installDirectory, started.WorkingDirectory);
        Assert.Contains("/c ", started.Arguments, StringComparison.Ordinal);
        Assert.Equal(installerPath, started.EnvironmentVariables[UpdateApplier.InstallerPathVariable]);
        Assert.False(string.IsNullOrEmpty(started.EnvironmentVariables[UpdateApplier.ExePathVariable]));

        // The bootstrapper is written next to the installer with the pure content.
        string bootstrapperPath = Path.Combine(installDirectory, "apply-update.cmd");
        Assert.True(File.Exists(bootstrapperPath));
        Assert.Equal(UpdateApplier.BuildBootstrapperContent(), File.ReadAllText(bootstrapperPath));
    }

    [Fact]
    public async Task apply_and_restart_reports_and_does_not_shut_down_when_process_fails_to_start()
    {
        string installerPath = CreateInstallerFile();
        var download = new AppDownloadResult(installerPath, HashOfInstaller());
        var sink = new RecordingErrorSink();
        var shutdownCount = 0;
        var applier = new UpdateApplier(
            sink,
            startProcess: _ => false,
            shutdown: () => shutdownCount++);

        bool applied = await applier.ApplyAndRestart(download);

        Assert.False(applied);
        Assert.True(sink.ContainsCode(UpdateApplier.LaunchFailedCode));
        Assert.Equal(0, shutdownCount);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static string HashOfInstaller()
    {
        return Convert.ToHexStringLower(SHA256.HashData(InstallerBytes));
    }

    private string CreateTempDirectory(string prefix = "update-applier-test-")
    {
        string directory = Path.Combine(
            Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        _tempDirectories.Add(directory);
        return directory;
    }

    private string CreateInstallerFile()
    {
        string installerPath = Path.Combine(CreateTempDirectory(), "setup.exe");
        File.WriteAllBytes(installerPath, InstallerBytes);
        return installerPath;
    }

    private sealed class RecordingErrorSink : IUiErrorSink
    {
        public List<(string Code, string Message)> Errors { get; } = new();

        public void Report(string code, string message) => Errors.Add((code, message));

        public bool ContainsCode(string code) => Errors.Exists(error => error.Code == code);
    }
}
