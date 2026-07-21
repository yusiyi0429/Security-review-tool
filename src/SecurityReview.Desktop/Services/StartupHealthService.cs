using System.ComponentModel;
using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.Desktop.Services;

public enum StartupHealthState { Checking, Ready, Blocked }

/// <summary>
/// Thin startup health surface. The desktop may open in Blocked state so users
/// can inspect diagnostics and history, but Start scan stays disabled; there is
/// no parser bypass. Diagnostics expose OS build and a worker hash prefix only
/// — never full local paths. Implements INotifyPropertyChanged so the shell
/// can react to health state changes without polling.
/// </summary>
public sealed class StartupHealthService : INotifyPropertyChanged
{
    private const int WorkerHashPrefixLength = 12;

    private StartupHealthState _state = StartupHealthState.Checking;
    private string? _blockedCode;

    public StartupHealthState State
    {
        get => _state;
        private set
        {
            if (_state == value) return;
            _state = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanStartScan));
        }
    }

    public string? BlockedCode
    {
        get => _blockedCode;
        private set
        {
            if (_blockedCode == value) return;
            _blockedCode = value;
            OnPropertyChanged();
        }
    }

    public string? OsBuild { get; private set; }
    public string? WorkerHashPrefix { get; private set; }

    public bool CanStartScan => State == StartupHealthState.Ready;

    public event PropertyChangedEventHandler? PropertyChanged;

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
            OnPropertyChanged(nameof(OsBuild));
        }

        if (!string.IsNullOrEmpty(workerSha256))
        {
            WorkerHashPrefix = workerSha256.Length > WorkerHashPrefixLength
                ? workerSha256[..WorkerHashPrefixLength]
                : workerSha256;
            OnPropertyChanged(nameof(WorkerHashPrefix));
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName!));
    }
}
