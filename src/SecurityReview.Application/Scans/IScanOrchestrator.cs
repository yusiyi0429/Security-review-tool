namespace SecurityReview.Application.Scans;

/// <summary>
/// Orchestrates a full scan from preflight through coverage reconciliation.
/// Produces a progress stream and a terminal outcome.
/// </summary>
public interface IScanOrchestrator
{
    /// <summary>
    /// Executes a scan rooted at <paramref name="scanRootPath"/>.
    /// Yields progress updates. Returns the terminal scan status.
    /// </summary>
    IAsyncEnumerable<ScanProgress> RunAsync(
        string scanRootPath,
        CancellationToken cancellationToken = default);
}
