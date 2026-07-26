using System.Runtime.CompilerServices;
using System.Threading.Channels;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Findings;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Default implementation of <see cref="IScanOrchestrator"/>. Coordinates
/// parse → detect → semantic → finalize. The orchestrator owns the scan
/// state machine and never mutates a previous scan's row.
///
/// For each parsed chunk, detectors run and every
/// <see cref="DetectionCandidate"/> is encrypted/persisted
/// immediately. Only candidates with
/// <see cref="DetectionCandidate.RequiresSemanticReview"/> are enqueued;
/// the orchestrator awaits the queue drain unless cancellation has been
/// requested. Deterministic detectors finish regardless of the LLM
/// result; unresolved candidates become <c>LlmUnresolved</c> gaps.
///
/// The orchestrator snapshots every file before parsing. The production
/// worker launcher verifies that hash again while opening a read-only handle;
/// a mismatch is recorded as <see cref="GapReason.FileUnstable"/> and yields
/// <see cref="ScanStatus.Partial"/>.
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly IInventoryService _inventoryService;
    private readonly IScanRepository _scanRepository;
    private readonly ScanPreflightService _preflightService;
    private readonly IManifestReader _manifestReader;
    private readonly IReadOnlyList<IFormatParser> _parsers;
    private readonly IWorkerJobProcessor _processor;
    private readonly IDetectionPipeline _detectionPipeline;
    private readonly IFindingRepository _findingRepository;
    private readonly ICoverageRepository _coverageRepository;
    private readonly IFileRepository _fileRepository;
    private readonly IFileSnapshotService? _fileSnapshotService;
    private readonly Func<ISemanticReviewQueue> _semanticQueueFactory;
    private readonly bool _disposeSemanticQueue = true;
    private readonly IDiagnosticSink _diagnosticSink;
    private readonly ScanOrchestratorState _state;
    private readonly Func<DateTimeOffset> _clock;

    public ScanOrchestrator(
        IInventoryService inventoryService,
        IScanRepository scanRepository,
        ScanPreflightService preflightService,
        IManifestReader manifestReader,
        IWorkerJobProcessor processor,
        IDetectionPipeline detectionPipeline,
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository,
        IFileRepository fileRepository,
        Func<ISemanticReviewQueue> semanticQueueFactory,
        IDiagnosticSink diagnosticSink,
        ScanOrchestratorState state,
        Func<DateTimeOffset>? clock = null,
        IFileSnapshotService? fileSnapshotService = null)
        : this(
            inventoryService,
            scanRepository,
            preflightService,
            manifestReader,
            Array.Empty<IFormatParser>(),
            processor,
            detectionPipeline,
            findingRepository,
            coverageRepository,
            fileRepository,
            semanticQueueFactory,
            diagnosticSink,
            state,
            clock,
            fileSnapshotService)
    {
    }

    public ScanOrchestrator(
        IInventoryService inventoryService,
        IScanRepository scanRepository,
        ScanPreflightService preflightService,
        IManifestReader manifestReader,
        IReadOnlyList<IFormatParser> parsers,
        IWorkerJobProcessor processor,
        IDetectionPipeline detectionPipeline,
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository,
        IFileRepository fileRepository,
        ISemanticReviewQueue semanticQueue,
        IDiagnosticSink diagnosticSink,
        ScanOrchestratorState state,
        Func<DateTimeOffset>? clock = null,
        IFileSnapshotService? fileSnapshotService = null)
        : this(
            inventoryService,
            scanRepository,
            preflightService,
            manifestReader,
            parsers,
            processor,
            detectionPipeline,
            findingRepository,
            coverageRepository,
            fileRepository,
            () => semanticQueue,
            diagnosticSink,
            state,
            clock,
            fileSnapshotService)
    {
        _disposeSemanticQueue = false;
    }

    public ScanOrchestrator(
        IInventoryService inventoryService,
        IScanRepository scanRepository,
        ScanPreflightService preflightService,
        IManifestReader manifestReader,
        IReadOnlyList<IFormatParser> parsers,
        IWorkerJobProcessor processor,
        IDetectionPipeline detectionPipeline,
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository,
        IFileRepository fileRepository,
        Func<ISemanticReviewQueue> semanticQueueFactory,
        IDiagnosticSink diagnosticSink,
        ScanOrchestratorState state,
        Func<DateTimeOffset>? clock = null,
        IFileSnapshotService? fileSnapshotService = null)
    {
        _inventoryService = inventoryService
            ?? throw new ArgumentNullException(nameof(inventoryService));
        _scanRepository = scanRepository
            ?? throw new ArgumentNullException(nameof(scanRepository));
        _preflightService = preflightService
            ?? throw new ArgumentNullException(nameof(preflightService));
        _manifestReader = manifestReader
            ?? throw new ArgumentNullException(nameof(manifestReader));
        _parsers = parsers
            ?? throw new ArgumentNullException(nameof(parsers));
        _processor = processor
            ?? throw new ArgumentNullException(nameof(processor));
        _detectionPipeline = detectionPipeline
            ?? throw new ArgumentNullException(nameof(detectionPipeline));
        _findingRepository = findingRepository
            ?? throw new ArgumentNullException(nameof(findingRepository));
        _coverageRepository = coverageRepository
            ?? throw new ArgumentNullException(nameof(coverageRepository));
        _fileRepository = fileRepository
            ?? throw new ArgumentNullException(nameof(fileRepository));
        _fileSnapshotService = fileSnapshotService;
        _semanticQueueFactory = semanticQueueFactory
            ?? throw new ArgumentNullException(nameof(semanticQueueFactory));
        _diagnosticSink = diagnosticSink
            ?? throw new ArgumentNullException(nameof(diagnosticSink));
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public async IAsyncEnumerable<ScanProgress> RunAsync(
        ScanId scanId,
        ScanConfigurationSnapshot? snapshot,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        Channel<ScanProgress> progressChannel = Channel.CreateUnbounded<ScanProgress>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = true,
                AllowSynchronousContinuations = false,
            });

        Task producer = ProduceRunAsync(
            scanId, snapshot, progressChannel.Writer, cancellationToken);

        await foreach (ScanProgress progress in progressChannel.Reader
            .ReadAllAsync(CancellationToken.None).ConfigureAwait(false))
        {
            yield return progress;
        }

        await producer.ConfigureAwait(false);
    }

    private async Task ProduceRunAsync(
        ScanId scanId,
        ScanConfigurationSnapshot? snapshot,
        ChannelWriter<ScanProgress> progressWriter,
        CancellationToken cancellationToken)
    {
        ScanOutcome? outcome = null;
        Exception? failure = null;

        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanStarted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.pipeline",
                ReasonCode = "start",
                Module = "Application.Scans",
                Method = "RunAsync",
            }));

        try
        {
            await TransitionToRunningAsync(scanId, cancellationToken)
                .ConfigureAwait(false);
            outcome = await RunPipelineAsync(
                    scanId, snapshot, ReportProgress, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _diagnosticSink.Publish(new DiagnosticEvent(
                DiagnosticCode.ScanCancelled, _clock(),
                scanId, "scan_cancelled",
                new DiagnosticFields
                {
                    Stage = "scan.pipeline",
                    ReasonCode = "cancelled",
                    Module = "Application.Scans",
                    Method = "RunAsync",
                }));

            ReportProgress(ScanProgress.Empty with { Stage = ScanStage.Cancelled });
            outcome = new ScanOutcome(scanId, ScanStatus.Cancelled,
                FindingCount: 0,
                UnresolvedSemanticCount: 0,
                GapCount: 0,
                CompletedAtUtc: _clock());
        }
        catch (Exception)
        {
            _diagnosticSink.Publish(new DiagnosticEvent(
                DiagnosticCode.ScanFailed, _clock(),
                scanId, "scan_failed",
                new DiagnosticFields
                {
                    Stage = "scan.pipeline",
                    ReasonCode = "exception",
                    Module = "Application.Scans",
                    Method = "RunAsync",
                }));

            ReportProgress(ScanProgress.Empty with { Stage = ScanStage.Failed });
            outcome = new ScanOutcome(scanId, ScanStatus.Failed,
                FindingCount: 0,
                UnresolvedSemanticCount: 0,
                GapCount: 0,
                CompletedAtUtc: _clock());
            failure = new InvalidOperationException("Scan pipeline failed.");
        }

        try
        {
            if (outcome is not null)
            {
                await PersistOutcomeAsync(outcome).ConfigureAwait(false);
                _state.Record(outcome);
            }

            if (failure is not null)
            {
                _diagnosticSink.Publish(new DiagnosticEvent(
                    DiagnosticCode.ScanFailed, _clock(),
                    scanId, "scan_failed",
                    new DiagnosticFields
                    {
                        Stage = "scan.pipeline",
                        ReasonCode = "pipeline_failed",
                        Module = "Application.Scans",
                        Method = "RunAsync",
                    }));
            }
        }
        finally
        {
            progressWriter.TryComplete();
        }

        void ReportProgress(ScanProgress progress)
        {
            progressWriter.TryWrite(progress);
        }
    }

    public Task<ScanOutcome?> GetOutcomeAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_state.Get(scanId));
    }

    private async Task<ScanOutcome> RunPipelineAsync(
        ScanId scanId,
        ScanConfigurationSnapshot? snapshot,
        Action<ScanProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        reportProgress(ScanProgress.Empty with { Stage = ScanStage.Preflight });

        if (snapshot is null)
        {
            reportProgress(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return FinaliseFailed(scanId, "snapshot_missing", 0, 0, 0);
        }

        string[] targets = snapshot.RootPaths;
        string firstTarget = targets.FirstOrDefault() ?? string.Empty;

        // The preflight gate is a fail-closed set of infrastructure checks
        // (sandbox, baseline, app data, database health). Run once at the
        // top of every scan.
        var preflightRequest = new ScanPreflightRequest(firstTarget);
        ScanPreflightResult preflight = await _preflightService
            .ValidateAsync(preflightRequest, cancellationToken)
            .ConfigureAwait(false);

        bool hasInvalidAdditionalTarget = targets.Skip(1).Any(
            target => !ScanPreflightService.IsExistingTarget(target));
        if (!preflight.CanStart || hasInvalidAdditionalTarget)
        {
            _diagnosticSink.Publish(new DiagnosticEvent(
                DiagnosticCode.ScanPreflightFailed, _clock(),
                scanId, null,
                new DiagnosticFields
                {
                    Stage = "scan.preflight",
                    ReasonCode = "preflight_failed",
                    Module = "Application.Scans",
                    Method = "RunPipelineAsync",
                }));

            reportProgress(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return FinaliseFailed(scanId, "preflight_failed", 0, 0, 0);
        }

        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanPreflightPassed, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.preflight",
                ReasonCode = "preflight_passed",
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        // ---- Step: Build inventory ----
        reportProgress(ScanProgress.Empty with { Stage = ScanStage.Inventory });

        InventoryResult inventory = await BuildInventoryAsync(
                scanId, snapshot, cancellationToken)
            .ConfigureAwait(false);

        if (inventory.Outcome != InventoryOutcome.Completed)
        {
            _diagnosticSink.Publish(new DiagnosticEvent(
                DiagnosticCode.ScanInventoryEmpty, _clock(),
                scanId, null,
                new DiagnosticFields
                {
                    Stage = "scan.inventory",
                    ReasonCode = inventory.FailureCode ?? "inventory_failed",
                    Module = "Application.Scans",
                    Method = "RunPipelineAsync",
                }));

            reportProgress(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return FinaliseFailed(scanId, inventory.FailureCode ?? "inventory_failed",
                0, 0, 0);
        }

        inventory = await CaptureFileSnapshotsAsync(
                scanId, snapshot, inventory, cancellationToken)
            .ConfigureAwait(false);

        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanInventoryCompleted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.inventory",
                ReasonCode = "inventory_completed",
                Count = inventory.Files.Count,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        // Findings and coverage gaps reference file_records through foreign
        // keys, so the inventory must be durable before parse/detect starts.
        // Persisting it as a batch also ensures a completed scan retains the
        // exact file set that was evaluated.
        await _fileRepository.InsertBatchAsync(scanId, inventory.Files, cancellationToken)
            .ConfigureAwait(false);

        var ledger = new InMemoryCoverageLedger(scanId);
        foreach (FileRecord file in inventory.Files)
        {
            ledger.RegisterFile(file.FileId, file.Length);
        }
        foreach (InventoryMetadataUnit unit in inventory.MetadataUnits)
        {
            ledger.RegisterMetadata(unit);
            ledger.TransitionMetadata(unit, CoverageStatus.Covered);
        }
        foreach (CoverageGap gap in inventory.Gaps)
        {
            ledger.AddGap(gap);
            await _coverageRepository.InsertAsync(gap, cancellationToken).ConfigureAwait(false);
        }
        var excludedFileIds = inventory.Gaps
            .Where(gap => gap.Reason == GapReason.UserExcluded
                && gap.FileId is not null)
            .Select(gap => gap.FileId!.Value)
            .ToHashSet();

        // ---- Step: Parse and detect ----
        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanParseDetectStarted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.parse_detect",
                ReasonCode = "started",
                Count = inventory.Files.Count,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        reportProgress(new ScanProgress(ScanStage.Running,
            DiscoveredFiles: inventory.Files.Count,
            ProcessedFiles: 0, FailedFiles: 0,
            PlannedBytes: inventory.Files.Sum(f => f.Length),
            ProcessedBytes: 0,
            ArchiveEntryCount: 0,
            FindingCount: 0, LlmQueueCount: 0,
            ActiveWorkerCount: 0,
            CurrentFileOrdinal: 0));

        var pendingFileIds = new HashSet<FileId>(inventory.Files.Select(f => f.FileId));
        var fileShaMap = new Dictionary<FileId, string>();
        ISemanticReviewQueue semanticQueue = _semanticQueueFactory()
            ?? throw new InvalidOperationException("Semantic review queue factory returned null.");
        using IDisposable? semanticQueueLease = _disposeSemanticQueue
            ? semanticQueue as IDisposable
            : null;
        int findingCount = 0;
        int failedFileCount = 0;
        int llmUnresolvedCount = 0;
        bool workerCancelled = false;
        int archiveEntryCount = 0;

        foreach (FileRecord file in inventory.Files)
        {
            fileShaMap[file.FileId] = file.ContentSha256 ?? string.Empty;
        }

        // The processor here drives the parser pipeline for one file at a
        // time. The harness or production wiring provides an
        // implementation backed by the parser worker pool.
        foreach (FileRecord file in inventory.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await IsCancellingAsync(scanId, cancellationToken).ConfigureAwait(false))
            {
                workerCancelled = true;
                break;
            }

            DateTimeOffset now = _clock();
            ParseLimits limits = ScanScheduler.CreateOrdinaryLimits(now);
            string virtualPath = file.RelativePath;
            string formatHint = file.FormatId ?? DetectFormatHint(virtualPath);
            var fileCandidates = new List<DetectionCandidate>();
            bool fileHadGap = false;
            bool fileFailed = false;
            bool fileCompleted = false;
            string? detectedFormatId = file.FormatId;

            if (excludedFileIds.Contains(file.FileId))
            {
                ledger.TransitionFile(file.FileId, CoverageStatus.NotCovered);
                pendingFileIds.Remove(file.FileId);
                await _fileRepository.UpdateAsync(
                        scanId,
                        file with { Coverage = CoverageStatus.NotCovered },
                        cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }

            if (_fileSnapshotService is not null
                && string.IsNullOrWhiteSpace(file.ContentSha256))
            {
                failedFileCount++;
                ledger.TransitionFile(file.FileId, CoverageStatus.NotCovered);
                pendingFileIds.Remove(file.FileId);
                await _fileRepository.UpdateAsync(
                        scanId,
                        file with { Coverage = CoverageStatus.NotCovered },
                        cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }

            var item = new ScanWorkItem(
                JobId: new JobId(Guid.NewGuid()),
                ScanId: scanId,
                FileId: file.FileId,
                VirtualPath: virtualPath,
                FormatHint: formatHint,
                DeclaredLength: file.Length,
                Limits: limits,
                IsOci: false,
                InputFilePath: BuildInputFilePath(
                    ResolveTargetRoot(snapshot.RootPaths[file.RootIndex]),
                    file),
                ExpectedContentSha256: file.ContentSha256);

            long metadataSequence = 0;
            foreach (InventoryMetadataUnit unit in inventory.MetadataUnits
                .Where(unit => unit.FileId == file.FileId))
            {
                ContentChunk metadataChunk = InventoryMetadataChunkAdapter.Convert(
                    unit, scanId, metadataSequence++);
                await foreach (DetectionCandidate candidate in _detectionPipeline
                    .DetectAsync(scanId, metadataChunk.JobId, file.FileId,
                        fileShaMap[file.FileId], metadataChunk.VirtualPath,
                        snapshot.ActiveRulePackHash,
                        file.ComponentAssetTypes,
                        metadataChunk, cancellationToken)
                    .ConfigureAwait(false))
                {
                    fileCandidates.Add(candidate);
                }
            }

            await foreach (WorkerJobResult result in _processor
                .ProcessAsync(item, cancellationToken)
                .ConfigureAwait(false))
            {
                switch (result.Kind)
                {
                    case WorkerResultKind.Chunk:
                        if (result.Chunk is not null)
                        {
                            detectedFormatId ??= result.Chunk.FormatId;
                            await foreach (DetectionCandidate candidate in _detectionPipeline
                                .DetectAsync(scanId, item.JobId, file.FileId,
                                    fileShaMap[file.FileId], virtualPath,
                                    snapshot.ActiveRulePackHash,
                                    file.ComponentAssetTypes,
                                    result.Chunk, cancellationToken)
                                .ConfigureAwait(false))
                            {
                                fileCandidates.Add(candidate);

                                if (candidate.RequiresSemanticReview)
                                {
                                    var queueItem = new SemanticQueueItem(
                                        CandidateId: candidate.Id,
                                        ScanId: scanId,
                                        Request: new SemanticReviewRequest(
                                            candidate.Id,
                                            CategoryId.Parse("SENS-001"),
                                            result.Chunk.ContentKind.ToString(),
                                            Path.GetExtension(virtualPath),
                                            virtualPath,
                                            result.Chunk.Text ?? string.Empty,
                                            candidate.Value,
                                            candidate.Locator,
                                            Array.Empty<DeterministicSecretSpan>()),
                                        RequiresSemanticReview: true,
                                        RulePackHash: snapshot!.ActiveRulePackHash,
                                        AdapterVersion: snapshot.DetectorAdapterVersion);

                                    bool enqueued = await semanticQueue
                                        .EnqueueAsync(queueItem, cancellationToken)
                                        .ConfigureAwait(false);
                                    if (!enqueued)
                                    {
                                        llmUnresolvedCount++;
                                        CoverageGap gap = BuildLlmUnresolvedGap(
                                            scanId, file, candidate.Id);
                                        ledger.AddGap(gap);
                                        await _coverageRepository
                                            .InsertAsync(gap, cancellationToken)
                                            .ConfigureAwait(false);
                                    }
                                }
                            }
                        }

                        break;

                    case WorkerResultKind.Gap:
                        if (result.Gap is not null)
                        {
                            fileHadGap = true;
                            ledger.AddGap(result.Gap);
                            await _coverageRepository.InsertAsync(
                                result.Gap, cancellationToken).ConfigureAwait(false);
                        }
                        break;

                    case WorkerResultKind.Failed:
                        fileFailed = true;
                        if (result.Gap is not null)
                        {
                            ledger.AddGap(result.Gap);
                            await _coverageRepository.InsertAsync(
                                result.Gap, cancellationToken).ConfigureAwait(false);
                        }
                        break;

                    case WorkerResultKind.Cancelled:
                        workerCancelled = true;
                        fileFailed = true;
                        break;

                    case WorkerResultKind.ChildDiscovered:
                        archiveEntryCount++;
                        break;

                    case WorkerResultKind.Completed:
                        fileCompleted = true;
                        break;
                }

                reportProgress(new ScanProgress(ScanStage.Running,
                    DiscoveredFiles: inventory.Files.Count,
                    ProcessedFiles: inventory.Files.Count - pendingFileIds.Count,
                    FailedFiles: failedFileCount + (fileFailed ? 1 : 0),
                    PlannedBytes: inventory.Files.Sum(f => f.Length),
                    ProcessedBytes: inventory.Files.Where(f => !pendingFileIds.Contains(f.FileId))
                        .Sum(f => f.Length),
                    ArchiveEntryCount: archiveEntryCount,
                    FindingCount: findingCount,
                    LlmQueueCount: semanticQueue.PendingCount,
                    ActiveWorkerCount: 0,
                    CurrentFileOrdinal: inventory.Files.Count - pendingFileIds.Count));
            }

            CoverageStatus coverage = fileFailed || !fileCompleted
                ? CoverageStatus.NotCovered
                : fileHadGap
                    ? CoverageStatus.PartiallyCovered
                    : CoverageStatus.Covered;
            ledger.TransitionFile(file.FileId, coverage);
            pendingFileIds.Remove(file.FileId);
            if (fileFailed || !fileCompleted)
            {
                failedFileCount++;
            }

            if (fileCandidates.Count > 0)
            {
                var merger = new CandidateMerger(
                    new MergeOnlyFingerprintService());
                IReadOnlyList<FindingGroup> groups = merger.Merge(
                    scanId, item.JobId, fileCandidates,
                    fileShaMap[file.FileId], virtualPath);

                foreach (FindingGroup group in groups)
                {
                    await _findingRepository.InsertGroupAsync(
                        scanId, group, cancellationToken).ConfigureAwait(false);
                    await _findingRepository.InsertOccurrenceBatchAsync(
                        file.FileId, group.Occurrences, cancellationToken)
                        .ConfigureAwait(false);
                }

                findingCount += fileCandidates.Count;
            }

            await _fileRepository.UpdateAsync(
                    scanId,
                    file with
                    {
                        FormatId = detectedFormatId,
                        Coverage = coverage,
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }

        workerCancelled |= await IsCancellingAsync(scanId, cancellationToken)
            .ConfigureAwait(false);

        // ---- Step: Drain semantic queue ----
        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanSemanticQueueStarted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.semantic_queue",
                ReasonCode = "started",
                Count = semanticQueue.PendingCount,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        if (!cancellationToken.IsCancellationRequested && !workerCancelled)
        {
            semanticQueue.CompleteAdding();
            try
            {
                await semanticQueue.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                semanticQueue.Cancel();
            }
        }
        else
        {
            semanticQueue.Cancel();
        }

        SemanticQueueProgress semanticProgress = semanticQueue.GetProgress();
        int semanticQueueIssueCount = semanticProgress.UnresolvedCount
            + semanticProgress.FailedCount
            + semanticProgress.CancelledCount;
        llmUnresolvedCount += semanticQueueIssueCount;
        for (int i = 0; i < semanticQueueIssueCount; i++)
        {
            CoverageGap gap = BuildSemanticQueueGap(
                scanId,
                semanticProgress.CancelledCount > i
                    ? "semantic_review_cancelled"
                    : semanticProgress.FailedCount
                        > i - semanticProgress.CancelledCount
                            ? "semantic_review_failed"
                            : "semantic_review_unresolved");
            ledger.AddGap(gap);
            await _coverageRepository
                .InsertAsync(gap, cancellationToken)
                .ConfigureAwait(false);
        }

        // ---- Step: Final reconciliation ----
        reportProgress(ScanProgress.Empty with { Stage = ScanStage.Reconciling });
        CoverageSummary summary = ledger.Reconcile();

        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanReconciliationCompleted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.reconciliation",
                ReasonCode = "completed",
                Count = summary.Gaps.Count,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        ScanStatus finalStatus = summary.FinalScanStatus(
            unresolvedSemanticCandidates: llmUnresolvedCount);

        if (workerCancelled || cancellationToken.IsCancellationRequested)
        {
            finalStatus = ScanStatus.Cancelled;
        }

        reportProgress(new ScanProgress(
            finalStatus switch
            {
                ScanStatus.Completed => ScanStage.Completed,
                ScanStatus.Cancelled => ScanStage.Cancelled,
                _ => ScanStage.Partial,
            },
            DiscoveredFiles: inventory.Files.Count,
            ProcessedFiles: inventory.Files.Count - pendingFileIds.Count,
            FailedFiles: failedFileCount,
            PlannedBytes: inventory.Files.Sum(f => f.Length),
            ProcessedBytes: inventory.Files.Where(f => !pendingFileIds.Contains(f.FileId))
                .Sum(f => f.Length),
            ArchiveEntryCount: archiveEntryCount,
            FindingCount: findingCount,
            LlmQueueCount: 0,
            ActiveWorkerCount: 0,
            CurrentFileOrdinal: inventory.Files.Count - pendingFileIds.Count));

        _diagnosticSink.Publish(new DiagnosticEvent(
            finalStatus == ScanStatus.Completed ? DiagnosticCode.ScanCompleted : DiagnosticCode.ScanFailed,
            _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = finalStatus == ScanStatus.Completed ? "scan.completed" : "scan.partial",
                ReasonCode = finalStatus == ScanStatus.Completed ? "completed" : "partial",
                Count = findingCount,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        return new ScanOutcome(scanId, finalStatus,
            FindingCount: findingCount,
            UnresolvedSemanticCount: llmUnresolvedCount,
            GapCount: summary.Gaps.Count,
            CompletedAtUtc: _clock());
    }

    private async Task<InventoryResult> CaptureFileSnapshotsAsync(
        ScanId scanId,
        ScanConfigurationSnapshot snapshot,
        InventoryResult inventory,
        CancellationToken cancellationToken)
    {
        if (_fileSnapshotService is null)
        {
            return inventory;
        }

        var files = new List<FileRecord>(inventory.Files.Count);
        var gaps = new List<CoverageGap>(inventory.Gaps);

        var excludedIds = inventory.Gaps
            .Where(gap => gap.Reason == GapReason.UserExcluded
                && gap.FileId is not null)
            .Select(gap => gap.FileId!.Value)
            .ToHashSet();

        foreach (FileRecord file in inventory.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (excludedIds.Contains(file.FileId))
            {
                files.Add(file);
                continue;
            }
            try
            {
                string root = ResolveTargetRoot(snapshot.RootPaths[file.RootIndex]);
                FileSnapshot captured = await _fileSnapshotService
                    .OpenAndHashAsync(root, file, cancellationToken)
                    .ConfigureAwait(false);

                if (captured.Identity != file.Identity)
                {
                    gaps.Add(BuildSnapshotGap(
                        scanId, file, GapReason.FileUnstable,
                        "identity_changed_before_parse"));
                    files.Add(file);
                    continue;
                }

                files.Add(file with
                {
                    Identity = captured.Identity,
                    Length = captured.Length,
                    LastWriteUtc = captured.LastWriteUtc,
                    ContentSha256 = captured.Sha256Hex,
                });
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                gaps.Add(BuildSnapshotGap(
                    scanId, file, GapReason.AccessDenied,
                    "snapshot_hash_failed"));
                files.Add(file);
            }
        }

        return inventory with
        {
            Files = files,
            Gaps = gaps,
        };
    }

    private static CoverageGap BuildSnapshotGap(
        ScanId scanId,
        FileRecord file,
        GapReason reason,
        string detailCode) =>
        new(
            Guid.NewGuid(),
            scanId,
            file.FileId,
            file.RelativePath,
            file.FormatId ?? DetectFormatHint(file.RelativePath),
            "snapshot",
            reason,
            detailCode,
            file.Length,
            0,
            DateTimeOffset.UtcNow);

    private async Task<InventoryResult> BuildInventoryAsync(
        ScanId scanId,
        ScanConfigurationSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        string[] targets = snapshot.RootPaths;
        var files = new List<FileRecord>();
        var metadata = new List<InventoryMetadataUnit>();
        var gaps = new List<CoverageGap>();
        var boundaries = new List<InventoryBoundaryRecord>();
        var seenFileIds = new HashSet<FileId>();
        long observedStreams = 0;
        long observedBytes = 0;
        AdsCapability adsCapability = AdsCapability.Available;

        for (int rootIndex = 0; rootIndex < targets.Length; rootIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string target = targets[rootIndex];
            string targetRoot = ResolveTargetRoot(target);

            ManifestSnapshot? manifestSnapshot = snapshot.RootManifests is not null
                && rootIndex < snapshot.RootManifests.Length
                    ? snapshot.RootManifests[rootIndex]
                    : rootIndex == 0
                        ? snapshot.Manifest
                        : null;
            IReadOnlyList<AssetComponent> components =
                manifestSnapshot?.Manifest?.Components
                ?? (IReadOnlyList<AssetComponent>)Array.Empty<AssetComponent>();

            long remainingStreams = InventoryRequest.DefaultMaxStreams - observedStreams;
            long remainingBytes = InventoryRequest.DefaultMaxTotalBytes - observedBytes;
            if (remainingStreams <= 0 || remainingBytes <= 0)
            {
                return new InventoryResult(
                    [], [], [], [], InventoryOutcome.InputScopeExceeded,
                    InventoryFailureCodes.InputScopeExceeded,
                    observedStreams, observedBytes, adsCapability);
            }

            var request = new InventoryRequest(
                scanId,
                target,
                components,
                remainingStreams,
                remainingBytes,
                rootIndex);
            InventoryResult result = await _inventoryService
                .BuildAsync(request, cancellationToken)
                .ConfigureAwait(false);

            observedStreams += result.ObservedStreamCount;
            observedBytes += result.ObservedTotalBytes;
            if (result.AdsCapability == AdsCapability.NotAvailableForFileSystem)
            {
                adsCapability = AdsCapability.NotAvailableForFileSystem;
            }

            if (result.Outcome != InventoryOutcome.Completed)
            {
                return result with
                {
                    ObservedStreamCount = observedStreams,
                    ObservedTotalBytes = observedBytes,
                    AdsCapability = adsCapability,
                };
            }

            var acceptedIds = new HashSet<FileId>();
            foreach (FileRecord file in result.Files)
            {
                if (seenFileIds.Add(file.FileId))
                {
                    files.Add(file);
                    acceptedIds.Add(file.FileId);
                }
                else
                {
                    boundaries.Add(new InventoryBoundaryRecord(
                        file.RelativePath,
                        InventoryBoundaryRecord.DuplicateIdentitySkipped));
                }
            }

            metadata.AddRange(result.MetadataUnits.Where(
                unit => acceptedIds.Contains(unit.FileId)));
            gaps.AddRange(result.Gaps.Where(
                gap => gap.FileId is null || acceptedIds.Contains(gap.FileId.Value)));
            boundaries.AddRange(result.BoundaryRecords);
        }

        string[] exclusionPatterns = snapshot.Exclusions?
            .Select(exclusion => exclusion.Pattern)
            .ToArray()
            ?? snapshot.ExclusionPatterns;
        var exclusionMatcher = new ExclusionMatcher(exclusionPatterns);
        foreach (FileRecord file in files)
        {
            if (!exclusionMatcher.IsMatch(file.RelativePath, file.StreamName))
            {
                continue;
            }

            gaps.Add(new CoverageGap(
                Guid.NewGuid(),
                scanId,
                file.FileId,
                file.RelativePath,
                file.FormatId ?? DetectFormatHint(file.RelativePath),
                "inventory",
                GapReason.UserExcluded,
                "user_excluded",
                file.Length,
                0,
                _clock()));
        }

        return new InventoryResult(
            [.. InventoryOrdering.Order(files)],
            metadata,
            gaps,
            boundaries,
            InventoryOutcome.Completed,
            null,
            observedStreams,
            observedBytes,
            adsCapability);
    }

    private async Task<bool> IsCancellingAsync(
        ScanId scanId,
        CancellationToken cancellationToken)
    {
        ScanRun? scan = await _scanRepository
            .GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        return scan?.Status is ScanStatus.Cancelling or ScanStatus.Cancelled;
    }

    private static string ResolveTargetRoot(string target)
    {
        string fullPath = Path.GetFullPath(target);
        if (!File.Exists(fullPath))
        {
            return fullPath;
        }

        return Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("File scan target has no parent directory.");
    }

    private static string BuildInputFilePath(string targetRoot, FileRecord file)
    {
        string path = Path.Combine(targetRoot,
            file.RelativePath.Replace('/', Path.DirectorySeparatorChar));
        if (file.StreamName is null)
        {
            return path;
        }

        if (file.StreamName.Length == 0
            || file.StreamName.IndexOfAny([':', '/', '\\', '\0', '.']) >= 0)
        {
            throw new InvalidOperationException("Invalid alternate data stream name.");
        }

        return path + ":" + file.StreamName;
    }

    private ScanOutcome FinaliseFailed(ScanId scanId, string reason,
        int findingCount, int unresolvedCount, int gapCount)
    {
        _ = reason;
        return new ScanOutcome(scanId, ScanStatus.Failed,
            FindingCount: findingCount,
            UnresolvedSemanticCount: unresolvedCount,
            GapCount: gapCount,
            CompletedAtUtc: _clock());
    }

    private async Task TransitionToRunningAsync(
        ScanId scanId,
        CancellationToken cancellationToken)
    {
        ScanRun? scan = await _scanRepository.GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (scan is null)
            throw new InvalidOperationException("Scan run is missing.");

        if (scan.Status == ScanStatus.Running)
            return;

        if (scan.Status != ScanStatus.Preflight
            || !await _scanRepository.TryTransitionAsync(
                scanId,
                ScanStatus.Preflight,
                scan.Version,
                ScanStatus.Running,
                cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Scan run could not enter Running state.");
        }
    }

    private async Task PersistOutcomeAsync(ScanOutcome outcome)
    {
        ScanRun? scan = await _scanRepository.GetByIdAsync(
            outcome.ScanId, CancellationToken.None).ConfigureAwait(false);
        if (scan is null)
            throw new InvalidOperationException("Scan run is missing during finalisation.");

        if (scan.Status == outcome.FinalStatus)
            return;

        if (outcome.FinalStatus == ScanStatus.Cancelled
            && scan.Status == ScanStatus.Running)
        {
            bool cancelling = await _scanRepository.TryTransitionAsync(
                outcome.ScanId,
                ScanStatus.Running,
                scan.Version,
                ScanStatus.Cancelling,
                CancellationToken.None).ConfigureAwait(false);
            if (!cancelling)
                throw new InvalidOperationException("Scan run could not enter Cancelling state.");

            scan = await _scanRepository.GetByIdAsync(
                outcome.ScanId, CancellationToken.None).ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    "Scan run is missing during cancellation finalisation.");
        }

        if (!ScanStateMachine.CanTransition(scan.Status, outcome.FinalStatus)
            || !await _scanRepository.TryTransitionAsync(
                outcome.ScanId,
                scan.Status,
                scan.Version,
                outcome.FinalStatus,
                CancellationToken.None).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Scan run terminal transition failed.");
        }
    }

    private static CoverageGap BuildLlmUnresolvedGap(
        ScanId scanId,
        FileRecord file,
        CandidateId candidateId)
    {
        _ = candidateId;
        return new CoverageGap(
            GapId: Guid.NewGuid(),
            ScanId: scanId,
            FileId: file.FileId,
            VirtualPath: file.RelativePath,
            FormatId: file.FormatId ?? "unknown",
            Stage: "semantic_review",
            Reason: GapReason.LlmUnresolved,
            DetailCode: "semantic_review_unresolved",
            PlannedBytes: file.Length,
            ProcessedBytes: 0,
            CreatedAtUtc: DateTimeOffset.UtcNow);
    }

    private static CoverageGap BuildSemanticQueueGap(
        ScanId scanId,
        string detailCode) =>
        new(
            GapId: Guid.NewGuid(),
            ScanId: scanId,
            FileId: null,
            VirtualPath: "(semantic-review)",
            FormatId: "semantic",
            Stage: "semantic_review",
            Reason: GapReason.LlmUnresolved,
            DetailCode: detailCode,
            PlannedBytes: null,
            ProcessedBytes: null,
            CreatedAtUtc: DateTimeOffset.UtcNow);

    private static string DetectFormatHint(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".json" => "json",
            ".xml" => "xml",
            ".yaml" or ".yml" => "yaml",
            ".csv" or ".tsv" => "csv",
            ".txt" or ".log" or ".md" or ".jsonl"
                or ".ini" or ".cfg" or ".conf" or ".html"
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

    private sealed class MergeOnlyFingerprintService : SecurityReview.Application.Abstractions.IValueFingerprintService
    {
        public SecurityReview.Domain.Findings.ValueFingerprint Compute(System.ReadOnlySpan<char> normalizedValue)
        {
            byte[] hash = System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(normalizedValue.ToString()));
            return new SecurityReview.Domain.Findings.ValueFingerprint(
                Convert.ToHexStringLower(hash));
        }
    }
}

/// <summary>
/// Process-wide record of scan outcomes produced by
/// <see cref="ScanOrchestrator"/>. The query service reads from this
/// map; persistence is handled separately through
/// <see cref="IScanRepository"/>.
/// </summary>
public sealed class ScanOrchestratorState
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<ScanId, ScanOutcome> _outcomes = new();

    public void Record(ScanOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        _outcomes[outcome.ScanId] = outcome;
    }

    public ScanOutcome? Get(ScanId scanId) => _outcomes.TryGetValue(scanId, out var v) ? v : null;
}
