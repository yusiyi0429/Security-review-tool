using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Transitions a Draft scan to Preflight, runs the bounded preflight
/// gate, and on success leaves the scan in <see cref="ScanStatus.Preflight"/>
/// ready to be handed to the orchestrator. The orchestrator itself
/// advances the scan to <see cref="ScanStatus.Running"/> and beyond —
/// <see cref="StartScanHandler"/> never owns terminal progress.
/// </summary>
public sealed class StartScanHandler
{
    private readonly IScanRepository _scanRepository;
    private readonly IScanSnapshotRepository _snapshotRepository;
    private readonly ScanPreflightService _preflight;
    private readonly ScanConfigurationSnapshotCodec _snapshotCodec;

    public StartScanHandler(
        IScanRepository scanRepository,
        IScanSnapshotRepository snapshotRepository,
        ScanPreflightService preflight,
        IPayloadProtector protector)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
        _preflight = preflight ?? throw new ArgumentNullException(nameof(preflight));
        _snapshotCodec = new ScanConfigurationSnapshotCodec(
            protector ?? throw new ArgumentNullException(nameof(protector)));
    }

    public async Task<StartScanResult> HandleAsync(
        ScanId scanId,
        CancellationToken cancellationToken = default)
    {
        ScanRun? existing = await _scanRepository.GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (existing is null)
        {
            return StartScanResult.Failed(
                new[] { new PreflightError("scan_not_found", "Scan does not exist.") });
        }

        if (existing.Status is not (ScanStatus.Draft or ScanStatus.Preflight))
        {
            return StartScanResult.Failed(new[]
            {
                new PreflightError("scan_not_startable",
                    $"Scan is in {existing.Status} and cannot be started.")
            });
        }

        ScanSnapshotRecord? snapshot = await _snapshotRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (snapshot is null)
        {
            return StartScanResult.Failed(new[]
            {
                new PreflightError("snapshot_missing",
                    "Scan configuration snapshot is missing.")
            });
        }

        ScanConfigurationSnapshot configuration;
        try
        {
            configuration = _snapshotCodec.Unprotect(snapshot);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return StartScanResult.Failed(new[]
            {
                new PreflightError("snapshot_invalid",
                    "Scan configuration snapshot is invalid or cannot be decrypted.")
            });
        }

        if (configuration.RootPaths.Length == 0)
        {
            return StartScanResult.Failed(new[]
            {
                new PreflightError("snapshot_invalid",
                    "Scan configuration snapshot contains no scan roots.")
            });
        }

        // Preflight currently probes the first root. The immutable snapshot,
        // rather than mutable UI state, is the source of truth.
        var preflightRequest = new ScanPreflightRequest(configuration.RootPaths[0]);
        ScanPreflightResult result = await _preflight
            .ValidateAsync(preflightRequest, cancellationToken)
            .ConfigureAwait(false);
        if (!result.CanStart)
        {
            return StartScanResult.Failed(result.Errors);
        }

        if (existing.Status == ScanStatus.Draft)
        {
            bool transitioned = await _scanRepository.TryTransitionAsync(
                scanId,
                ScanStatus.Draft,
                existing.Version,
                ScanStatus.Preflight,
                cancellationToken).ConfigureAwait(false);
            if (!transitioned)
            {
                return StartScanResult.Failed(new[]
                {
                    new PreflightError("scan_transition_conflict",
                        "Scan status changed concurrently.")
                });
            }
        }

        return StartScanResult.Succeeded(scanId, snapshot.ConfigHash, configuration);
    }
}

/// <summary>
/// Outcome of <see cref="StartScanHandler"/>.
/// </summary>
public sealed record StartScanResult(
    bool Started,
    ScanId? ScanId,
    string? ConfigHash,
    IReadOnlyList<PreflightError> Errors,
    ScanConfigurationSnapshot? Snapshot)
{
    public static StartScanResult Succeeded(
        ScanId scanId,
        string configHash,
        ScanConfigurationSnapshot snapshot) =>
        new(true, scanId, configHash, Array.Empty<PreflightError>(), snapshot);

    public static StartScanResult Failed(IReadOnlyList<PreflightError> errors) =>
        new(false, null, null, errors, null);
}
