using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diff;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Creates a brand-new scan using the current inputs and configuration,
/// leaving the previous scan immutable. The new scan reuses the strict
/// caches, computes a diff against the previous scan, and invalidates
/// any non-matching exception grants (those grants remain valid for
/// the old scan only).
/// </summary>
public sealed class RescanHandler
{
    private readonly IScanRepository _scanRepository;
    private readonly CreateScanHandler _createScan;
    private readonly Func<DateTimeOffset> _clock;

    public RescanHandler(
        IScanRepository scanRepository,
        CreateScanHandler createScan,
        Func<DateTimeOffset>? clock = null)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _createScan = createScan ?? throw new ArgumentNullException(nameof(createScan));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Creates a fresh scan from <paramref name="command"/> (which
    /// carries the current UI inputs and configuration). The previous
    /// scan identified by <paramref name="previousScanId"/> stays
    /// untouched — the diff service compares the new scan's findings
    /// against it after the orchestrator completes.
    /// </summary>
    public async Task<RescanResult> HandleAsync(
        ScanId? previousScanId,
        CreateScanCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Verify the previous scan exists when one is provided — the
        // diff service anchors on the new scan's id, so the caller must
        // hand us a real scan.
        if (previousScanId is { } previous && await _scanRepository
            .GetByIdAsync(previous, cancellationToken).ConfigureAwait(false) is null)
        {
            return RescanResult.Failed("previous_scan_not_found");
        }

        CreateScanResult created = await _createScan
            .HandleAsync(command, cancellationToken)
            .ConfigureAwait(false);
        if (!created.Created || created.ScanId is null)
        {
            return RescanResult.Failed(string.Join(",",
                created.Errors.Select(e => e.Code)));
        }

        return RescanResult.Succeeded(created.ScanId.Value, previousScanId, created.ConfigHash ?? string.Empty);
    }
}

/// <summary>
/// Outcome of <see cref="RescanHandler.HandleAsync"/>.
/// </summary>
public sealed record RescanResult(
    bool Created,
    string? FailureCode,
    ScanId? NewScanId,
    ScanId? PreviousScanId,
    string? ConfigHash)
{
    public static RescanResult Failed(string code) =>
        new(false, code, null, null, null);

    public static RescanResult Succeeded(ScanId newScanId, ScanId? previousScanId, string configHash) =>
        new(true, null, newScanId, previousScanId, configHash);
}
