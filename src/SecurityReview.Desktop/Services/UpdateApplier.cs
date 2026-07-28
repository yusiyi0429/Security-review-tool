using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using SecurityReview.Application.Updates;

namespace SecurityReview.Desktop.Services;

/// <summary>
/// Applies a downloaded update: re-verifies the installer against the digest
/// verified at download time, writes a small cmd bootstrapper next to the
/// installer that runs it silently (<c>/VERYSILENT /NORESTART</c>) and then
/// relaunches the application, starts the bootstrapper detached, and shuts
/// the application down. Every failure path (missing installer, hash
/// mismatch, unwritable bootstrapper, failed process start) reports through
/// <see cref="IUiErrorSink"/> with a stable code and a sanitized Chinese
/// message and returns <c>false</c> — the apply callback is awaited by the
/// update view model and must never throw, so user-decline and verification
/// failures cannot be mis-mapped into the download error taxonomy, and the
/// boolean result tells the caller whether the installer actually started.
/// </summary>
public sealed class UpdateApplier
{
    /// <summary>Stable error code: installer missing or failed re-verification.</summary>
    public const string VerificationFailedCode = "update_apply_verification_failed";

    /// <summary>Stable error code: bootstrapper could not be written or started.</summary>
    public const string LaunchFailedCode = "update_apply_launch_failed";

    /// <summary>
    /// Environment variable that carries the installer path to the
    /// bootstrapper. Paths travel through the child process environment
    /// (Unicode-safe via CreateProcess) instead of being inlined into the
    /// .cmd file: cmd parses batch files in the system codepage, so a
    /// non-ASCII user name in the per-user temp path would garble an
    /// inlined path.
    /// </summary>
    public const string InstallerPathVariable = "SRT_UPDATE_INSTALLER";

    /// <summary>Environment variable that carries the application exe path to the bootstrapper.</summary>
    public const string ExePathVariable = "SRT_UPDATE_EXE";

    private const string BootstrapperFileName = "apply-update.cmd";

    private readonly IUiErrorSink _errorSink;
    private readonly Func<ProcessStartInfo, bool> _startProcess;
    private readonly Action _shutdown;

    /// <summary>
    /// Creates the applier. <paramref name="startProcess"/> and
    /// <paramref name="shutdown"/> are test seams; production wiring uses
    /// the defaults (detached <see cref="Process"/> start and
    /// <see cref="Application.Shutdown()"/>).
    /// </summary>
    public UpdateApplier(
        IUiErrorSink errorSink,
        Func<ProcessStartInfo, bool>? startProcess = null,
        Action? shutdown = null)
    {
        _errorSink = errorSink ?? throw new ArgumentNullException(nameof(errorSink));
        _startProcess = startProcess ?? StartProcessDetached;
        _shutdown = shutdown ?? ShutdownCurrentApplication;
    }

    /// <summary>
    /// Re-verifies the installer, writes and launches the bootstrapper,
    /// then shuts the application down. Reports and returns <c>false</c>
    /// on any failure; returns <c>true</c> only after the bootstrapper was
    /// started and shutdown was requested. Never throws.
    /// </summary>
    public async Task<bool> ApplyAndRestart(AppDownloadResult download)
    {
        ArgumentNullException.ThrowIfNull(download);

        // Re-verify immediately before executing: the file may have been
        // tampered with or cleaned up since the download completed. Hashing
        // a 100-500MB installer takes seconds, so keep it off the UI thread
        // (ConfigureAwait(true) resumes on the caller's context for the
        // process start and shutdown below).
        if (!await Task.Run(() => VerifyInstaller(download)).ConfigureAwait(true))
        {
            _errorSink.Report(
                VerificationFailedCode,
                "安装文件已丢失或未通过完整性校验，无法继续安装。请重新检查更新，或前往发布页手动下载。");
            return false;
        }

        string? exePath = Environment.ProcessPath;
        string? installDirectory = Path.GetDirectoryName(download.InstallerPath);
        if (string.IsNullOrEmpty(exePath) || string.IsNullOrEmpty(installDirectory))
        {
            ReportLaunchFailed();
            return false;
        }

        // The bootstrapper lives in the same ACL'd temp directory as the
        // installer (no new path dependencies). Its file name is a fixed
        // ASCII name, so `cmd /c` needs no quoting at all.
        string bootstrapperPath = Path.Combine(installDirectory, BootstrapperFileName);
        try
        {
            File.WriteAllText(bootstrapperPath, BuildBootstrapperContent());
        }
        catch
        {
            // IOException / UnauthorizedAccessException etc. — report and stay alive.
            ReportLaunchFailed();
            return false;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c {BootstrapperFileName}",
            WorkingDirectory = installDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.EnvironmentVariables[InstallerPathVariable] = download.InstallerPath;
        startInfo.EnvironmentVariables[ExePathVariable] = exePath;

        if (!_startProcess(startInfo))
        {
            ReportLaunchFailed();
            return false;
        }

        _shutdown();
        return true;
    }

    /// <summary>
    /// Re-computes the installer's SHA-256 and compares it with
    /// <see cref="AppDownloadResult.VerifiedSha256"/> (case-insensitive).
    /// Missing file, I/O failure, or mismatch all return false (fail closed).
    /// </summary>
    public static bool VerifyInstaller(AppDownloadResult download)
    {
        ArgumentNullException.ThrowIfNull(download);

        try
        {
            if (!File.Exists(download.InstallerPath))
            {
                return false;
            }

            using var stream = new FileStream(
                download.InstallerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var actualHash = Convert.ToHexStringLower(SHA256.HashData(stream));
            return string.Equals(actualHash, download.VerifiedSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Any I/O failure means we cannot trust the file — fail closed.
            return false;
        }
    }

    /// <summary>
    /// Builds the cmd bootstrapper content: run the installer silently
    /// without rebooting, relaunch the application, then delete both the
    /// installer and the bootstrapper itself so no update artifacts are
    /// left in the temp directory. Pure and ASCII-only by construction —
    /// paths are referenced through <see cref="InstallerPathVariable"/> /
    /// <see cref="ExePathVariable"/> so no quoting or codepage escaping is
    /// ever needed. Inno <c>/VERYSILENT</c> runs synchronously inside cmd,
    /// so the deletions below only execute after the install completes;
    /// <c>start</c> detaches the relaunch, so it is not affected.
    /// </summary>
    public static string BuildBootstrapperContent()
    {
        return "@echo off\r\n" +
               $"\"%{InstallerPathVariable}%\" /VERYSILENT /NORESTART\r\n" +
               $"start \"\" \"%{ExePathVariable}%\"\r\n" +
               $"del \"%{InstallerPathVariable}%\"\r\n" +
               "del \"%~f0\"\r\n";
    }

    private void ReportLaunchFailed()
    {
        _errorSink.Report(
            LaunchFailedCode,
            "无法启动安装程序。请前往发布页手动下载并安装。");
    }

    private static bool StartProcessDetached(ProcessStartInfo startInfo)
    {
        try
        {
            return Process.Start(startInfo) is not null;
        }
        catch
        {
            return false;
        }
    }

    private static void ShutdownCurrentApplication()
    {
        Application.Current?.Shutdown();
    }
}
