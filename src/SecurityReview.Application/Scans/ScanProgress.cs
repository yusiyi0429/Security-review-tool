namespace SecurityReview.Application.Scans;

/// <summary>
/// Lightweight progress snapshot emitted during a scan. Never exposes
/// absolute paths, relative paths, or content.
/// </summary>
public sealed record ScanProgress(
    ScanStage Stage,
    int DiscoveredFiles,
    int ProcessedFiles,
    int FailedFiles,
    long PlannedBytes,
    long ProcessedBytes,
    int ArchiveEntryCount,
    int FindingCount,
    int LlmQueueCount,
    int ActiveWorkerCount,
    int CurrentFileOrdinal)
{
    public static readonly ScanProgress Empty = new(
        ScanStage.Draft, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

/// <summary>High-level scan stage reported in progress events.</summary>
public enum ScanStage
{
    Draft,
    Preflight,
    Inventory,
    Running,
    Reconciling,
    Completed,
    Partial,
    Cancelled,
    Failed,
    Interrupted,
}
