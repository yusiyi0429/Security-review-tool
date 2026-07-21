using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Marks an in-flight scan as cancelling. The orchestrator polls the
/// status flag on each iteration and stops scheduling new work; the
/// terminal <see cref="ScanStatus.Cancelled"/> transition is performed
/// by the orchestrator itself when it observes the flag.
/// </summary>
public sealed class CancelScanHandler
{
    private readonly IScanRepository _scanRepository;
    private readonly Func<DateTimeOffset> _clock;

    public CancelScanHandler(
        IScanRepository scanRepository,
        Func<DateTimeOffset>? clock = null)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public async Task<bool> HandleAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        ScanRun? existing = await _scanRepository.GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (existing is null)
        {
            return false;
        }

        // Already terminal — nothing to do.
        if (existing.Status is ScanStatus.Completed or ScanStatus.Partial
            or ScanStatus.Cancelled or ScanStatus.Failed or ScanStatus.Interrupted)
        {
            return false;
        }

        return await _scanRepository.TryTransitionAsync(
            scanId,
            existing.Status,
            existing.Version,
            ScanStatus.Cancelling,
            cancellationToken).ConfigureAwait(false);
    }
}
