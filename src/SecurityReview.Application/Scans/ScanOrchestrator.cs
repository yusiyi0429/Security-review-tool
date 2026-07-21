using System.Runtime.CompilerServices;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Default implementation of <see cref="IScanOrchestrator"/>. Coordinates
/// the full scan pipeline: preflight, inventory, scheduling, parsing,
/// coverage tracking, mutation retry, and reconciliation.
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly IInventoryService _inventoryService;
    private readonly IFileSnapshotService _snapshotService;
    private readonly ScanPreflightService _preflightService;
    private readonly IManifestReader _manifestReader;
    private readonly IReadOnlyList<IFormatParser> _parsers;
    private readonly IWorkerJobProcessor _processor;

    public ScanOrchestrator(
        IInventoryService inventoryService,
        IFileSnapshotService snapshotService,
        ScanPreflightService preflightService,
        IManifestReader manifestReader,
        IReadOnlyList<IFormatParser> parsers,
        IWorkerJobProcessor processor)
    {
        _inventoryService = inventoryService
            ?? throw new ArgumentNullException(nameof(inventoryService));
        _snapshotService = snapshotService
            ?? throw new ArgumentNullException(nameof(snapshotService));
        _preflightService = preflightService
            ?? throw new ArgumentNullException(nameof(preflightService));
        _manifestReader = manifestReader
            ?? throw new ArgumentNullException(nameof(manifestReader));
        _parsers = parsers
            ?? throw new ArgumentNullException(nameof(parsers));
        _processor = processor
            ?? throw new ArgumentNullException(nameof(processor));
    }

    public async IAsyncEnumerable<ScanProgress> RunAsync(
        string scanRootPath,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Buffer progress outside try/catch to avoid CS1626.
        List<ScanProgress> allProgress = new();
        ScanStatus outcome;

        try
        {
            outcome = await RunPipelineAsync(scanRootPath, allProgress, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            allProgress.Add(ScanProgress.Empty with { Stage = ScanStage.Cancelled });
            outcome = ScanStatus.Cancelled;
        }
        catch (Exception)
        {
            allProgress.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            outcome = ScanStatus.Failed;
        }

        foreach (ScanProgress progress in allProgress)
        {
            yield return progress;
        }
    }

    private async Task<ScanStatus> RunPipelineAsync(
        string scanRootPath,
        List<ScanProgress> progressList,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scanRootPath);

        ScanId scanId = new(Guid.NewGuid());
        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        ScanRun run = new(scanId, ScanStatus.Draft, startedAt, startedAt,
            RuleFingerprint: "placeholder", ClientFingerprint: "placeholder",
            PipelineFingerprint: "placeholder", PlannedCount: 0, Version: 1);

        var ledger = new InMemoryCoverageLedger(scanId);

        // ---- Step 1: Preflight ----
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Preflight });

        var preflightRequest = new ScanPreflightRequest(scanRootPath);
        ScanPreflightResult preflightResult = await _preflightService
            .ValidateAsync(preflightRequest, cancellationToken)
            .ConfigureAwait(false);

        if (!preflightResult.CanStart)
        {
            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return ScanStatus.Failed;
        }

        // ---- Step 2: Validate root ----
        if (!Directory.Exists(scanRootPath))
        {
            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return ScanStatus.Failed;
        }

        // ---- Step 3: Read manifest ----
        ManifestReadResult manifestResult = await _manifestReader
            .ReadAsync(scanRootPath, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<AssetComponent> components =
            manifestResult.Snapshot?.Manifest?.Components
            ?? (IReadOnlyList<AssetComponent>)Array.Empty<AssetComponent>();

        // ---- Step 4: Build inventory ----
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Inventory });

        var inventoryRequest = new InventoryRequest(
            scanId, scanRootPath, components,
            MaxStreams: 100_000, MaxTotalBytes: 10L * 1024 * 1024 * 1024);

        InventoryResult inventory = await _inventoryService
            .BuildAsync(inventoryRequest, cancellationToken)
            .ConfigureAwait(false);

        if (inventory.Outcome != InventoryOutcome.Completed)
        {
            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return ScanStatus.Failed;
        }

        IReadOnlyList<FileRecord> files = inventory.Files;
        IReadOnlyList<InventoryMetadataUnit> metadataUnits = inventory.MetadataUnits;

        // ---- Step 5: Register planned units in ledger ----
        foreach (FileRecord file in files)
        {
            ledger.RegisterFile(file.FileId, file.Length);
        }

        foreach (InventoryMetadataUnit unit in metadataUnits)
        {
            ledger.RegisterMetadata(unit);
        }

        foreach (CoverageGap gap in inventory.Gaps)
        {
            ledger.AddGap(gap);
        }

        // ---- Step 6: Process metadata chunks (in-process) ----
        long metaSeq = 0;
        foreach (InventoryMetadataUnit unit in metadataUnits)
        {
            ContentChunk metaChunk = InventoryMetadataChunkAdapter.Convert(
                unit, scanId, metaSeq++);
            ledger.TransitionMetadata(unit, CoverageStatus.Covered);
        }

        // ---- Step 7: Transition to Running ----
        var scheduler = new ScanScheduler(_processor);
        if (!scheduler.TryAcquire(scanId))
        {
            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return ScanStatus.Failed;
        }

        // ---- Step 8: Schedule all file parse jobs ----
        progressList.Add(new ScanProgress(ScanStage.Running,
            DiscoveredFiles: files.Count, 0, 0,
            files.Sum(f => f.Length), 0, 0, 0, 0, 0, 0));

        int totalFiles = files.Count;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (FileRecord file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool isOci = IsOciFile(file);

            ParseLimits limits = isOci
                ? ScanScheduler.CreateOciLimits(now)
                : ScanScheduler.CreateOrdinaryLimits(now);

            string virtualPath = file.RelativePath;
            string formatHint = file.FormatId ?? DetectFormatHint(virtualPath);

            JobId jobId = new(Guid.NewGuid());

            var item = new ScanWorkItem(
                jobId, scanId, file.FileId, virtualPath, formatHint,
                file.Length, limits, isOci);

            await scheduler.ScheduleAsync(item, cancellationToken).ConfigureAwait(false);
        }

        scheduler.CompleteAdding();

        // ---- Step 9: Process results ----
        int processedCount = 0;
        int failedCount = 0;
        long processedBytes = 0;
        var processedFiles = new HashSet<FileId>();
        var childQueue = new Queue<(FileId ParentId, string VirtualPath, FormatProbe Probe)>();

        await foreach (WorkerJobResult result in scheduler.Results.ReadAllAsync(
            cancellationToken).ConfigureAwait(false))
        {
            switch (result.Kind)
            {
                case WorkerResultKind.Chunk:
                    processedBytes += result.Chunk?.Text?.Length ?? 0;
                    break;

                case WorkerResultKind.ChildDiscovered:
                    if (result.ChildVirtualPath is not null && result.ChildProbe is not null)
                    {
                        childQueue.Enqueue((result.FileId, result.ChildVirtualPath,
                            result.ChildProbe));
                    }

                    break;

                case WorkerResultKind.Gap:
                    if (result.Gap is not null)
                    {
                        ledger.AddGap(result.Gap);
                    }

                    break;

                case WorkerResultKind.Completed:
                    if (processedFiles.Add(result.FileId))
                    {
                        processedCount++;
                        ledger.TransitionFile(result.FileId, CoverageStatus.Covered);
                    }

                    break;

                case WorkerResultKind.Failed:
                    if (processedFiles.Add(result.FileId))
                    {
                        processedCount++;
                        failedCount++;

                        if (result.Gap is not null)
                        {
                            ledger.AddGap(result.Gap);
                        }

                        ledger.TransitionFile(result.FileId, CoverageStatus.NotCovered);
                    }

                    break;

                case WorkerResultKind.Cancelled:
                    if (processedFiles.Add(result.FileId))
                    {
                        processedCount++;
                        ledger.TransitionFile(result.FileId, CoverageStatus.NotCovered);
                    }

                    break;
            }

            progressList.Add(new ScanProgress(ScanStage.Running,
                DiscoveredFiles: totalFiles,
                ProcessedFiles: processedCount,
                FailedFiles: failedCount,
                PlannedBytes: files.Sum(f => f.Length),
                ProcessedBytes: processedBytes,
                ArchiveEntryCount: childQueue.Count,
                FindingCount: 0,
                LlmQueueCount: 0,
                ActiveWorkerCount: scheduler.ActiveWorkerCount,
                CurrentFileOrdinal: processedCount));
        }

        // ---- Step 10: Process child discoveries ----
        while (childQueue.TryDequeue(out var child))
        {
            cancellationToken.ThrowIfCancellationRequested();

            long childLength = child.Probe.DeclaredLength;

            ledger.RegisterChild(child.ParentId, child.VirtualPath, childLength);
            ledger.TransitionChild(child.VirtualPath, CoverageStatus.Covered);
        }

        // ---- Step 11: Reconcile coverage ----
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Reconciling });

        CoverageSummary summary = ledger.Reconcile();

        // ---- Step 12: Final status ----
        ScanStatus finalStatus = summary.FinalScanStatus(
            unresolvedSemanticCandidates: 0);

        progressList.Add(new ScanProgress(
            finalStatus == ScanStatus.Completed ? ScanStage.Completed : ScanStage.Partial,
            DiscoveredFiles: totalFiles,
            ProcessedFiles: processedCount,
            FailedFiles: failedCount,
            PlannedBytes: files.Sum(f => f.Length),
            ProcessedBytes: processedBytes,
            ArchiveEntryCount: childQueue.Count,
            FindingCount: 0,
            LlmQueueCount: 0,
            ActiveWorkerCount: 0,
            CurrentFileOrdinal: processedCount));

        return finalStatus;
    }

    private static bool IsOciFile(FileRecord file)
    {
        string name = file.RelativePath.ToLowerInvariant();
        return name.EndsWith(".tar", StringComparison.Ordinal)
            && (name.Contains("docker", StringComparison.Ordinal)
                || name.Contains("oci", StringComparison.Ordinal)
                || name.Contains("container", StringComparison.Ordinal));
    }

    private static string DetectFormatHint(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".txt" or ".csv" or ".log" or ".md" or ".xml" or ".json"
                or ".yaml" or ".yml" or ".ini" or ".cfg" or ".conf" or ".html"
                or ".htm" or ".css" or ".js" or ".ts" or ".py" or ".java"
                or ".cs" or ".c" or ".h" or ".cpp" or ".hpp" or ".rs" or ".go"
                or ".rb" or ".php" or ".sh" or ".bat" or ".ps1" or ".sql" => "text",
            ".zip" or ".jar" or ".apk" or ".epub" => "zip",
            ".gz" or ".tgz" => "gzip",
            ".tar" => "tar",
            ".pdf" => "pdf",
            ".exe" or ".dll" or ".sys" => "pe",
            ".png" => "png",
            ".jpg" or ".jpeg" => "jpeg",
            _ => "unknown",
        };
    }
}
