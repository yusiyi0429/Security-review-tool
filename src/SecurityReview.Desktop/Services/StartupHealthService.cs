using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.Desktop.Services;

public enum StartupHealthState { Checking, Ready, Blocked }

// Thin startup health surface. The desktop may open in Blocked state so users
// can inspect diagnostics and history, but Start scan stays disabled; there is
// no parser bypass. Diagnostics expose OS build and a worker hash prefix only
// — never full local paths.
public sealed class StartupHealthService
{
    private const int WorkerHashPrefixLength = 12;

    public StartupHealthState State { get; private set; } = StartupHealthState.Checking;
    public string? BlockedCode { get; private set; }
    public string? OsBuild { get; private set; }
    public string? WorkerHashPrefix { get; private set; }

    public bool CanStartScan => State == StartupHealthState.Ready;

    public void ApplyPreflight(ScanPreflightResult result, string? osBuild,
        string? workerSha256)
    {
        ArgumentNullException.ThrowIfNull(result);
        SetDiagnostics(osBuild, workerSha256);
        if (result.CanStart)
        {
            MarkReady();
            return;
        }

        string code = result.Errors.Count > 0
            ? result.Errors[0].Code
            : PreflightErrorCodes.SandboxUnavailable;
        MarkBlocked(code);
    }

    public void MarkReady()
    {
        State = StartupHealthState.Ready;
        BlockedCode = null;
    }

    public void MarkBlocked(string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        State = StartupHealthState.Blocked;
        BlockedCode = code;
    }

    public void SetDiagnostics(string? osBuild, string? workerSha256)
    {
        if (!string.IsNullOrEmpty(osBuild))
        {
            OsBuild = osBuild;
        }

        if (!string.IsNullOrEmpty(workerSha256))
        {
            WorkerHashPrefix = workerSha256.Length > WorkerHashPrefixLength
                ? workerSha256[..WorkerHashPrefixLength]
                : workerSha256;
        }
    }
}
