using System.Runtime.CompilerServices;
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
/// The orchestrator re-hashes every file and applies one mutation retry
/// before the final reconciliation. The first mutation accepts on the
/// retry; a second mutation marks the file <see cref="GapReason.FileUnstable"/>
/// and yields <see cref="ScanStatus.Partial"/>.
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
    private readonly ISemanticReviewQueue _semanticQueue;
    private readonly IDiagnosticSink _diagnosticSink;
    private readonly ScanOrchestratorState _state;
    private readonly Func<DateTimeOffset> _clock;

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
        Func<DateTimeOffset>? clock = null)
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
        _semanticQueue = semanticQueue
            ?? throw new ArgumentNullException(nameof(semanticQueue));
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
        var progress = new List<ScanProgress>();
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
            outcome = await RunPipelineAsync(scanId, snapshot, progress, cancellationToken)
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

            progress.Add(ScanProgress.Empty with { Stage = ScanStage.Cancelled });
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

            progress.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            outcome = new ScanOutcome(scanId, ScanStatus.Failed,
                FindingCount: 0,
                UnresolvedSemanticCount: 0,
                GapCount: 0,
                CompletedAtUtc: _clock());
            failure = new InvalidOperationException("Scan pipeline failed.");
        }

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

        foreach (ScanProgress p in progress)
        {
            yield return p;
        }
    }

    public Task<ScanOutcome?> GetOutcomeAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_state.Get(scanId));
    }

    private async Task<ScanOutcome> RunPipelineAsync(
        ScanId scanId,
        ScanConfigurationSnapshot? snapshot,
        List<ScanProgress> progressList,
        CancellationToken cancellationToken)
    {
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Preflight });

        if (snapshot is null)
        {
            return new ScanOutcome(scanId, ScanStatus.Failed,
                FindingCount: 0, UnresolvedSemanticCount: 0, GapCount: 0,
                CompletedAtUtc: _clock());
        }

        string firstRoot = snapshot.RootPaths.FirstOrDefault() ?? string.Empty;

        // The preflight gate is a fail-closed set of infrastructure checks
        // (sandbox, baseline, app data, database health). Run once at the
        // top of every scan.
        var preflightRequest = new ScanPreflightRequest(firstRoot);
        ScanPreflightResult preflight = await _preflightService
            .ValidateAsync(preflightRequest, cancellationToken)
            .ConfigureAwait(false);

        if (!preflight.CanStart)
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

            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return FinaliseFailed(scanId, "preflight_failed", progressList, 0, 0, 0);
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

        // ---- Step: Read manifest ----
        ManifestReadResult manifestResult = await _manifestReader
            .ReadAsync(firstRoot, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<AssetComponent> components =
            manifestResult.Snapshot?.Manifest?.Components
            ?? (IReadOnlyList<AssetComponent>)Array.Empty<AssetComponent>();

        // ---- Step: Build inventory ----
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Inventory });

        var inventoryRequest = new InventoryRequest(
            scanId, firstRoot, components,
            MaxStreams: 100_000, MaxTotalBytes: 10L * 1024 * 1024 * 1024);

        InventoryResult inventory = await _inventoryService
            .BuildAsync(inventoryRequest, cancellationToken)
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

            progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Failed });
            return FinaliseFailed(scanId, inventory.FailureCode ?? "inventory_failed",
                progressList, 0, 0, 0);
        }

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

        var ledger = new InMemoryCoverageLedger(scanId);
        foreach (FileRecord file in inventory.Files)
        {
            ledger.RegisterFile(file.FileId, file.Length);
        }
        foreach (InventoryMetadataUnit unit in inventory.MetadataUnits)
        {
            ledger.RegisterMetadata(unit);
        }
        foreach (CoverageGap gap in inventory.Gaps)
        {
            ledger.AddGap(gap);
            await _coverageRepository.InsertAsync(gap, cancellationToken).ConfigureAwait(false);
        }

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

        progressList.Add(new ScanProgress(ScanStage.Running,
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
        var filePathMap = new Dictionary<FileId, string>();
        int findingCount = 0;
        int llmUnresolvedCount = 0;
        bool workerCancelled = false;

        foreach (FileRecord file in inventory.Files)
        {
            fileShaMap[file.FileId] = file.ContentSha256 ?? string.Empty;
            filePathMap[file.FileId] = file.RelativePath;
        }

        // The processor here drives the parser pipeline for one file at a
        // time. The harness or production wiring provides an
        // implementation backed by the parser worker pool.
        foreach (FileRecord file in inventory.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DateTimeOffset now = _clock();
            ParseLimits limits = ScanScheduler.CreateOrdinaryLimits(now);
            string virtualPath = file.RelativePath;
            string formatHint = file.FormatId ?? DetectFormatHint(virtualPath);

            var item = new ScanWorkItem(
                JobId: new JobId(Guid.NewGuid()),
                ScanId: scanId,
                FileId: file.FileId,
                VirtualPath: virtualPath,
                FormatHint: formatHint,
                DeclaredLength: file.Length,
                Limits: limits,
                IsOci: false,
                InputFilePath: Path.Combine(firstRoot, file.RelativePath));

            await foreach (WorkerJobResult result in _processor
                .ProcessAsync(item, cancellationToken)
                .ConfigureAwait(false))
            {
                switch (result.Kind)
                {
                    case WorkerResultKind.Chunk:
                        if (result.Chunk is not null)
                        {
                            await foreach (DetectionCandidate candidate in _detectionPipeline
                                .DetectAsync(scanId, item.JobId, file.FileId,
                                    fileShaMap[file.FileId], virtualPath,
                                    result.Chunk, cancellationToken)
                                .ConfigureAwait(false))
                            {
                                findingCount++;

                                var merger = new CandidateMerger(
                                    new MergeOnlyFingerprintService());
                                IReadOnlyList<FindingGroup> groups = merger.Merge(
                                    scanId, item.JobId,
                                    new[] { candidate },
                                    fileShaMap[file.FileId], virtualPath);

                                foreach (FindingGroup group in groups)
                                {
                                    await _findingRepository.InsertGroupAsync(
                                        scanId, group, cancellationToken).ConfigureAwait(false);
                                    foreach (FindingOccurrence occ in group.Occurrences)
                                    {
                                        await _findingRepository.InsertOccurrenceAsync(
                                            file.FileId, occ, cancellationToken).ConfigureAwait(false);
                                    }
                                }

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

                                    bool enqueued = await _semanticQueue
                                        .EnqueueAsync(queueItem, cancellationToken)
                                        .ConfigureAwait(false);
                                    if (!enqueued)
                                    {
                                        llmUnresolvedCount++;
                                        ledger.AddGap(BuildLlmUnresolvedGap(file, candidate.Id));
                                    }
                                }
                            }
                        }

                        break;

                    case WorkerResultKind.Gap:
                        if (result.Gap is not null)
                        {
                            ledger.AddGap(result.Gap);
                            await _coverageRepository.InsertAsync(
                                result.Gap, cancellationToken).ConfigureAwait(false);
                        }
                        break;

                    case WorkerResultKind.Failed:
                        if (result.Gap is not null)
                        {
                            ledger.AddGap(result.Gap);
                            await _coverageRepository.InsertAsync(
                                result.Gap, cancellationToken).ConfigureAwait(false);
                        }
                        ledger.TransitionFile(file.FileId, CoverageStatus.NotCovered);
                        pendingFileIds.Remove(file.FileId);
                        break;

                    case WorkerResultKind.Cancelled:
                        workerCancelled = true;
                        ledger.TransitionFile(file.FileId, CoverageStatus.NotCovered);
                        pendingFileIds.Remove(file.FileId);
                        break;

                    case WorkerResultKind.Completed:
                        ledger.TransitionFile(file.FileId, CoverageStatus.Covered);
                        pendingFileIds.Remove(file.FileId);
                        break;
                }

                progressList.Add(new ScanProgress(ScanStage.Running,
                    DiscoveredFiles: inventory.Files.Count,
                    ProcessedFiles: inventory.Files.Count - pendingFileIds.Count,
                    FailedFiles: 0,
                    PlannedBytes: inventory.Files.Sum(f => f.Length),
                    ProcessedBytes: inventory.Files.Where(f => !pendingFileIds.Contains(f.FileId))
                        .Sum(f => f.Length),
                    ArchiveEntryCount: 0,
                    FindingCount: findingCount,
                    LlmQueueCount: _semanticQueue.PendingCount,
                    ActiveWorkerCount: 0,
                    CurrentFileOrdinal: inventory.Files.Count - pendingFileIds.Count));
            }
        }

        // ---- Step: Drain semantic queue ----
        _diagnosticSink.Publish(new DiagnosticEvent(
            DiagnosticCode.ScanSemanticQueueStarted, _clock(),
            scanId, null,
            new DiagnosticFields
            {
                Stage = "scan.semantic_queue",
                ReasonCode = "started",
                Count = _semanticQueue.PendingCount,
                Module = "Application.Scans",
                Method = "RunPipelineAsync",
            }));

        if (!cancellationToken.IsCancellationRequested)
        {
            _semanticQueue.CompleteAdding();
            try
            {
                await _semanticQueue.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                _semanticQueue.Cancel();
            }
        }
        else
        {
            _semanticQueue.Cancel();
        }

        SemanticQueueProgress semanticProgress = _semanticQueue.GetProgress();
        llmUnresolvedCount += semanticProgress.UnresolvedCount
            + semanticProgress.FailedCount
            + semanticProgress.CancelledCount;

        // ---- Step: Final reconciliation ----
        progressList.Add(ScanProgress.Empty with { Stage = ScanStage.Reconciling });
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

        progressList.Add(new ScanProgress(
            finalStatus switch
            {
                ScanStatus.Completed => ScanStage.Completed,
                ScanStatus.Cancelled => ScanStage.Cancelled,
                _ => ScanStage.Partial,
            },
            DiscoveredFiles: inventory.Files.Count,
            ProcessedFiles: inventory.Files.Count - pendingFileIds.Count,
            FailedFiles: 0,
            PlannedBytes: inventory.Files.Sum(f => f.Length),
            ProcessedBytes: inventory.Files.Where(f => !pendingFileIds.Contains(f.FileId))
                .Sum(f => f.Length),
            ArchiveEntryCount: 0,
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

    private ScanOutcome FinaliseFailed(ScanId scanId, string reason, List<ScanProgress> progressList,
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

    private static CoverageGap BuildLlmUnresolvedGap(FileRecord file, CandidateId candidateId)
    {
        _ = candidateId;
        return new CoverageGap(
            GapId: Guid.NewGuid(),
            ScanId: new ScanId(Guid.Empty),
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
