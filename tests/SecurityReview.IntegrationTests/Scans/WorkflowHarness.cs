using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Findings;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Repositories;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.IntegrationTests.Scans;

/// <summary>
/// Self-contained fake that wires every dependency the orchestrator needs
/// without relying on Windows-only services. The harness lets each test
/// pin a specific scenario: no candidates, candidates with the LLM up or
/// down, file mutations, root failure, and cancellation.
/// </summary>
internal sealed class WorkflowHarness
{
    private readonly SqliteScanRepository _scans;
    private readonly SqliteFindingRepository _findings;
    private readonly SqliteCoverageRepository _coverage;
    private readonly SqliteScanSnapshotRepository _snapshots;
    private readonly FakeInventoryService _inventory;
    private readonly FakeSemanticQueue _semanticQueue;
    private readonly FakeDetectionPipeline _detection;
    private readonly ScanPreflightService _preflight;
    private readonly ScanOrchestrator _orchestrator;
    private readonly CreateScanHandler _create;
    private readonly StartScanHandler _start;
    private readonly CancelScanHandler _cancel;
    private readonly ScanConfigurationSnapshotCodec _snapshotCodec;

    private readonly DirectoryInfo? _root;
    private readonly SemanticOutcome _semanticOutcome;
    private readonly bool _emitCandidate;
    private readonly bool _rootMissing;
    private readonly string? _fileToMutateOnce;
    private readonly string? _fileToMutateTwice;
    private readonly bool _simulateCancel;

    public int FindingCount => _detection.TotalCandidatesEmitted;
    public int UnresolvedSemanticCount => _semanticQueue.UnresolvedPersisted;
    public int GapCount => _coverageGapCount;
    public IReadOnlyList<CoverageGap> ObservedGaps => _coverageObservedGaps;
    public IScanRepository Scans => _scans;

    private int _coverageGapCount;
    private IReadOnlyList<CoverageGap> _coverageObservedGaps = Array.Empty<CoverageGap>();

    public WorkflowHarness(
        ISqliteConnectionFactory factory,
        IPayloadProtector protector,
        IValueFingerprintService fingerprint,
        DirectoryInfo? root,
        SemanticOutcome semanticOutcome = SemanticOutcome.NoCandidates,
        bool? emitCandidate = null,
        bool rootMissing = false,
        bool simulateCancel = false,
        string? fileToMutateOnce = null,
        string? fileToMutateTwice = null,
        bool includeArchiveCorrupt = false)
    {
        _root = root;
        _semanticOutcome = semanticOutcome;
        _emitCandidate = emitCandidate ?? semanticOutcome != SemanticOutcome.NoCandidates;
        _rootMissing = rootMissing;
        _fileToMutateOnce = fileToMutateOnce;
        _fileToMutateTwice = fileToMutateTwice;
        _simulateCancel = simulateCancel;
        _ = includeArchiveCorrupt;

        _scans = new SqliteScanRepository(factory, protector);
        _findings = new SqliteFindingRepository(factory, protector, fingerprint);
        _coverage = new SqliteCoverageRepository(factory, protector);
        _snapshots = new SqliteScanSnapshotRepository(factory);
        _snapshotCodec = new ScanConfigurationSnapshotCodec(protector);

        _inventory = new FakeInventoryService(_root, _rootMissing, _fileToMutateOnce, _fileToMutateTwice);
        _semanticQueue = new FakeSemanticQueue();
        _detection = new FakeDetectionPipeline(emitCandidate: _emitCandidate);
        var state = new ScanOrchestratorState();

        var reviewer = new FakeSemanticReviewer(_semanticQueue, _semanticOutcome);
        _semanticQueue.AttachReviewer(reviewer);

        _preflight = new ScanPreflightService(
            new AlwaysPassSandbox(),
            new AlwaysPassBaseline(),
            new AlwaysPassSpace(),
            new AlwaysPassDatabase());

        _orchestrator = new ScanOrchestrator(
            _inventory,
            _scans,
            _preflight,
            new NullManifestReader(),
            Array.Empty<IFormatParser>(),
            new FakeProcessor(_detection, _root, _fileToMutateOnce, _fileToMutateTwice,
                _simulateCancel, includeArchiveCorrupt),
            _detection,
            _findings,
            _coverage,
            new NullFileRepository(),
            _semanticQueue,
            new NullDiagnosticSink(),
            state);

        _create = new CreateScanHandler(_scans, _snapshots, protector);
        _start = new StartScanHandler(_scans, _snapshots, _preflight, protector);
        _cancel = new CancelScanHandler(_scans);
    }

    public async Task<ScanId> CreateAndStartAsync()
    {
        var sandbox = new SandboxSelfTestResult(
            Passed: true, Code: "ok", WorkerSha256: "test-worker",
            OsBuild: "test-build", ProfileSid: "test-profile",
            CheckedAtUtc: DateTimeOffset.UtcNow);

        var manifestSnapshot = new ManifestSnapshot(
            Manifest: new AssetManifest(
                AssetId: "asset-1",
                AssetVersion: "1.0",
                Components: EmptyAssetComponents,
                Evidence: new ComplianceEvidence(
                    new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
                    new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
                    Array.Empty<ThirdPartyAuthorization>())),
            OriginalSha256: "manifest-hash",
            Valid: true,
            Errors: Array.Empty<ManifestValidationError>());

        var command = new CreateScanCommand(
            RootPaths: BuildRootPaths(_root),
            Manifest: manifestSnapshot,
            UiOverrideComponentIds: EmptyStrings,
            ExclusionPatterns: EmptyStrings,
            ActiveRulePackHash: "rule-pack-hash-1",
            PolicySha256: "policy-sha-1",
            LlmEndpointFingerprint: "endpoint-fp-1",
            LlmModelFingerprint: "model-fp-1",
            ClientVersion: "client-v1",
            ParserAdapterVersion: "parser-v1",
            DetectorAdapterVersion: "detector-v1",
            PromptVersion: "prompt-v1",
            Sandbox: sandbox,
            EffectiveDetectorVersions: SingleDetectorVersions);

        CreateScanResult created = await _create.HandleAsync(command);
        if (!created.Created || created.ScanId is null)
        {
            throw new InvalidOperationException(
                $"CreateScanHandler refused: {string.Join(", ", created.Errors.Select(e => e.Code))}");
        }

        StartScanResult started = await _start.HandleAsync(created.ScanId.Value);
        if (!started.Started)
        {
            throw new InvalidOperationException(
                $"StartScanHandler refused: {string.Join(", ", started.Errors.Select(e => e.Code))}");
        }

        return created.ScanId.Value;
    }

    public async Task RunAsync(ScanId scanId, CancellationToken cancellationToken)
    {
        ScanSnapshotRecord? snapshot = await _snapshots
            .GetByScanIdAsync(scanId, cancellationToken);

        ScanConfigurationSnapshot? configuration = snapshot is null
            ? null
            : _snapshotCodec.Unprotect(snapshot);

        await foreach (ScanProgress _ in _orchestrator
            .RunAsync(scanId, configuration!, cancellationToken)
            .WithCancellation(cancellationToken))
        {
            // Drain progress events; the orchestrator writes the outcome to its state map.
        }

        _coverageGapCount = (await _coverage.GetByScanIdAsync(scanId, cancellationToken)).Count;
        _coverageObservedGaps = await _coverage.GetByScanIdAsync(scanId, cancellationToken);
    }

    public string CurrentConfigHashFor(ScanId scanId)
    {
        return _snapshots.Get(scanId)?.ConfigHash
            ?? throw new InvalidOperationException("Snapshot missing.");
    }

    private static readonly string[] EmptyStrings = Array.Empty<string>();
    private static readonly IReadOnlyList<AssetComponent> EmptyAssetComponents = Array.Empty<AssetComponent>();
    private static readonly IReadOnlyList<LocationMapEntry> EmptyLocationMap = Array.Empty<LocationMapEntry>();
    private static readonly string[] SingleDetectorVersions = new[] { "detector-v1" };
    private static readonly string[] MissingRootPath = new[] { "/missing" };

    private static string[] BuildRootPaths(DirectoryInfo? root)
        => root is not null ? new[] { root.FullName } : MissingRootPath;
}

// ------------------------------------------------------------------
// Fake plumbing — kept in a separate file so the test class stays focused.
// ------------------------------------------------------------------

internal sealed class AlwaysPassSandbox : ISandboxSelfTest
{
    public Task<SandboxSelfTestResult> RunAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new SandboxSelfTestResult(
            Passed: true, Code: "ok", WorkerSha256: "w", OsBuild: "b", ProfileSid: "p",
            CheckedAtUtc: DateTimeOffset.UtcNow));
}

internal sealed class AlwaysPassBaseline : ISignedBaselineProvider
{
    public Task<bool> HasActiveSignedBaselineAsync(CancellationToken cancellationToken) => Task.FromResult(true);
}

internal sealed class AlwaysPassSpace : IAppDataSpaceProbe
{
    public Task<bool> HasWritableSpaceAsync(CancellationToken cancellationToken) => Task.FromResult(true);
}

internal sealed class AlwaysPassDatabase : IDatabaseHealthCheck
{
    public Task<bool> IsHealthyAsync(CancellationToken cancellationToken) => Task.FromResult(true);
}

internal sealed class NullManifestReader : IManifestReader
{
    public Task<ManifestReadResult> ReadAsync(string scanRootPath, CancellationToken cancellationToken) =>
        Task.FromResult(ManifestReadResult.NotFound);
}

internal sealed class NullFileRepository : IFileRepository
{
    public Task InsertAsync(ScanId scanId, FileRecord file, CancellationToken ct = default) => Task.CompletedTask;
    public Task InsertBatchAsync(ScanId scanId, IReadOnlyList<FileRecord> files, CancellationToken ct = default) => Task.CompletedTask;
    public Task<FileRecord?> GetByIdAsync(FileId fileId, CancellationToken ct = default) => Task.FromResult<FileRecord?>(null);
    public Task<IReadOnlyList<FileRecord>> GetByScanIdAsync(ScanId scanId, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<FileRecord>>(Array.Empty<FileRecord>());
    public Task<int> CountByScanIdAsync(ScanId scanId, CancellationToken ct = default) => Task.FromResult(0);
}

internal sealed class NullDiagnosticSink : IDiagnosticSink
{
    public void Publish(DiagnosticEvent diagnosticEvent) { _ = diagnosticEvent; }
}

internal sealed class FakeDetectionPipeline : IDetectionPipeline
{
    private readonly bool _emitCandidate;
    private int _totalEmitted;

    public FakeDetectionPipeline(bool emitCandidate) => _emitCandidate = emitCandidate;

    public int TotalCandidatesEmitted => _totalEmitted;

    public async IAsyncEnumerable<DetectionCandidate> DetectAsync(
        ScanId scanId,
        JobId jobId,
        FileId fileId,
        string fileSha256,
        string virtualPath,
        ContentChunk chunk,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!_emitCandidate)
        {
            yield break;
        }

        if (chunk.Text is null)
        {
            yield break;
        }

        const string sentinel = "SECRET-CANDIDATE";
        int index = chunk.Text.IndexOf(sentinel, StringComparison.Ordinal);
        if (index < 0)
        {
            yield break;
        }

        var locator = new SourceLocator.TextLocator(1, index, index, sentinel.Length);
        DetectionCandidate candidate = DetectionCandidate.Create(
            sentinel,
            chunk.Text,
            locator,
            new RuleId("RULE-DEMO"),
            new DetectorId("DET-DEMO"),
            Severity.High,
            DetectionConfidence.High,
            FindingKind.SensitiveContent,
            requiresSemanticReview: true);

        _totalEmitted++;
        await Task.Yield();
        yield return candidate;
    }
}

internal sealed class FakeSemanticReviewer : ISemanticReviewer
{
    private readonly FakeSemanticQueue _queue;
    private readonly SemanticOutcome _outcome;

    public FakeSemanticReviewer(FakeSemanticQueue queue, SemanticOutcome outcome)
    {
        _queue = queue;
        _outcome = outcome;
    }

    public async Task<LlmReviewResult> ReviewAsync(
        SemanticReviewRequest request, CancellationToken cancellationToken = default)
    {
        await Task.Delay(1, cancellationToken).ConfigureAwait(false);

        if (_outcome == SemanticOutcome.EndpointDown)
        {
            _queue.MarkUnresolved(request.CandidateId);
            return new LlmReviewResult
            {
                CandidateId = request.CandidateId,
                Classification = SemanticClassification.Unresolved,
                ReasonCode = "endpoint_unavailable"
            };
        }

        return new LlmReviewResult
        {
            CandidateId = request.CandidateId,
            Classification = SemanticClassification.Confirmed,
            CategoryId = CategoryId.Parse("SENS-001"),
            Confidence = 0.95,
            ReasonCode = "ok",
            PromptVersion = "v1"
        };
    }
}

internal sealed class FakeSemanticQueue : ISemanticReviewQueue, ISemanticCandidateLifetime,
    ISemanticReviewPersister, ISemanticReviewProgressSink
{
    private readonly ConcurrentDictionary<CandidateId, bool> _unresolved = new();
    private ISemanticReviewer _reviewer = null!;
    private int _completed;
    private int _failed;
    private int _cancelled;
    private int _pending;

    public int MaxConsumers => 2;
    public int Capacity => 1000;
    public int PendingCount => Volatile.Read(ref _pending);
    public int UnresolvedPersisted => _unresolved.Count;

    public void AttachReviewer(ISemanticReviewer reviewer) => _reviewer = reviewer;

    public void MarkUnresolved(CandidateId id) => _unresolved[id] = true;

    public ValueTask<bool> EnqueueAsync(SemanticQueueItem item, CancellationToken cancellationToken)
    {
        if (!item.RequiresSemanticReview) return ValueTask.FromResult(false);
        if (cancellationToken.IsCancellationRequested) return ValueTask.FromResult(false);
        Interlocked.Increment(ref _pending);
        return ValueTask.FromResult(true);
    }

    public void CompleteAdding() { /* no-op */ }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (_pending > 0 && !cancellationToken.IsCancellationRequested)
        {
            Interlocked.Decrement(ref _pending);
            try
            {
                LlmReviewResult result = await _reviewer.ReviewAsync(
                    new SemanticReviewRequest(
                        CandidateId: new CandidateId(Guid.NewGuid()),
                        CategoryHint: default,
                        ContentKind: "text",
                        Extension: ".txt",
                        VirtualPath: "synthetic",
                        FullContext: string.Empty,
                        CandidateValue: string.Empty,
                        CandidateLocator: new SourceLocator.TextLocator(0, 0, 0, 0),
                        DeterministicSecrets: Array.Empty<DeterministicSecretSpan>()),
                    cancellationToken).ConfigureAwait(false);

                if (result.Classification == SemanticClassification.Unresolved
                    && IsCurrent(new CandidateId(Guid.NewGuid())))
                {
                    var persisted = new PersistedLlmReview(
                        CandidateId: result.CandidateId,
                        ScanId: new ScanId(Guid.Empty),
                        CacheKey: string.Empty,
                        Classification: result.Classification,
                        CategoryId: result.CategoryId?.Value ?? "SENS-001",
                        Confidence: result.Confidence,
                        ReasonCode: result.ReasonCode ?? "unresolved",
                        InjectionDetected: result.InjectionDetected,
                        PromptSha256: result.PromptSha256 ?? string.Empty,
                        PromptVersion: result.PromptVersion ?? string.Empty,
                        EndpointFingerprint: string.Empty,
                        ModelFingerprint: string.Empty,
                        AttemptedAtUtc: DateTimeOffset.UtcNow,
                        Duration: TimeSpan.Zero,
                        Attempts: 1);
                    await PersistAsync(persisted, cancellationToken).ConfigureAwait(false);
                }

                Interlocked.Increment(ref _completed);
            }
            catch (OperationCanceledException)
            {
                Interlocked.Increment(ref _cancelled);
                break;
            }
            catch
            {
                Interlocked.Increment(ref _failed);
            }
        }
    }

    public void Cancel() { _pending = 0; }

    public SemanticQueueProgress GetProgress() => new(
        PendingCount: _pending, ActiveCount: 0, CompletedCount: _completed,
        FailedCount: _failed, CancelledCount: _cancelled,
        UnresolvedCount: _unresolved.Count,
        LastUpdatedAtUtc: DateTimeOffset.UtcNow);

    public bool IsCurrent(CandidateId candidateId) => !_unresolved.ContainsKey(candidateId);

    public async Task PersistAsync(PersistedLlmReview review, CancellationToken cancellationToken)
    {
        if (review.Classification == SemanticClassification.Unresolved)
        {
            _unresolved[review.CandidateId] = true;
        }
        await Task.CompletedTask;
    }

    public void Publish(SemanticQueueProgress progress) { _ = progress; }
}

internal sealed class FakeInventoryService : IInventoryService
{
    private readonly DirectoryInfo? _root;
    private readonly bool _rootMissing;

    public FakeInventoryService(DirectoryInfo? root, bool rootMissing, string? mutateOnce, string? mutateTwice)
    {
        _root = root;
        _rootMissing = rootMissing;
        _ = mutateOnce;
        _ = mutateTwice;
    }

    public string RootPath => _root?.FullName ?? string.Empty;

    public Task<InventoryResult> BuildAsync(InventoryRequest request, CancellationToken cancellationToken)
    {
        if (_rootMissing || _root is null)
        {
            return Task.FromResult(new InventoryResult(
                Files: Array.Empty<FileRecord>(),
                MetadataUnits: Array.Empty<InventoryMetadataUnit>(),
                Gaps: Array.Empty<CoverageGap>(),
                BoundaryRecords: Array.Empty<InventoryBoundaryRecord>(),
                Outcome: InventoryOutcome.RootFailed,
                FailureCode: InventoryFailureCodes.RootUnavailable,
                ObservedStreamCount: 0,
                ObservedTotalBytes: 0,
                AdsCapability: AdsCapability.NotAvailableForFileSystem));
        }

        var files = new List<FileRecord>();
        long totalBytes = 0;
        foreach (FileInfo f in _root.EnumerateFiles("*", SearchOption.AllDirectories))
        {
            FileRecord record = BuildRecord(f, totalIndex: files.Count);
            files.Add(record);
            totalBytes += f.Length;
        }

        return Task.FromResult(new InventoryResult(
            Files: files,
            MetadataUnits: Array.Empty<InventoryMetadataUnit>(),
            Gaps: Array.Empty<CoverageGap>(),
            BoundaryRecords: Array.Empty<InventoryBoundaryRecord>(),
            Outcome: InventoryOutcome.Completed,
            FailureCode: null,
            ObservedStreamCount: files.Count,
            ObservedTotalBytes: totalBytes,
            AdsCapability: AdsCapability.NotAvailableForFileSystem));
    }

    private FileRecord BuildRecord(FileInfo f, int totalIndex)
    {
        try
        {
            string existing = File.ReadAllText(f.FullName);
            if (!existing.Contains("SECRET-CANDIDATE", StringComparison.Ordinal))
            {
                File.AppendAllText(f.FullName, Environment.NewLine + "SECRET-CANDIDATE=abc" + Environment.NewLine);
            }
        }
        catch
        {
            // ignore — file may be locked by a concurrent mutation
        }

        FileInfo refresh = new(f.FullName);
        FileId id = new(Guid.NewGuid());
        string sha = $"sha-{totalIndex:D4}";

        return new FileRecord(
            FileId: id,
            RootIndex: 0,
            RelativePath: Path.GetRelativePath(_root!.FullName, f.FullName),
            EncryptedPathPlaceholder: null,
            StreamName: null,
            Length: refresh.Length,
            LastWriteUtc: refresh.LastWriteTimeUtc,
            Attributes: refresh.Attributes,
            Identity: new FileStreamIdentity(
                VolumeSerial: "vol-0",
                FileIndex: (UInt128)(totalIndex + 1),
                StreamName: null),
            ComponentAssetTypes: Array.Empty<AssetTypeId>(),
            Status: InventoryStatus.Complete,
            FormatId: "text",
            ContentSha256: sha,
            Coverage: CoverageStatus.NotCovered);
    }
}

internal sealed class FakeProcessor : IWorkerJobProcessor
{
    private readonly FakeDetectionPipeline _detection;
    private readonly DirectoryInfo? _root;
    private readonly string? _mutateOnce;
    private readonly string? _mutateTwice;
    private readonly bool _simulateCancel;
    private readonly bool _includeArchiveCorrupt;

    public FakeProcessor(
        FakeDetectionPipeline detection,
        DirectoryInfo? root,
        string? mutateOnce,
        string? mutateTwice,
        bool simulateCancel,
        bool includeArchiveCorrupt)
    {
        _detection = detection;
        _root = root;
        _mutateOnce = mutateOnce;
        _mutateTwice = mutateTwice;
        _simulateCancel = simulateCancel;
        _includeArchiveCorrupt = includeArchiveCorrupt;
    }

    public async IAsyncEnumerable<WorkerJobResult> ProcessAsync(
        ScanWorkItem item,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (_mutateOnce is not null && string.Equals(item.VirtualPath,
                Path.GetFileName(_mutateOnce), StringComparison.OrdinalIgnoreCase))
        {
            await MutateFile(_mutateOnce, "BBBBBBBB");
        }

        if (_mutateTwice is not null && string.Equals(item.VirtualPath,
                Path.GetFileName(_mutateTwice), StringComparison.OrdinalIgnoreCase))
        {
            await MutateFile(_mutateTwice, "CCCCCCCC");
            await MutateFile(_mutateTwice, "DDDDDDDD");
        }

        if (_simulateCancel)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return new WorkerJobResult(
                item.JobId, item.FileId, WorkerResultKind.Cancelled,
                Chunk: null, Gap: null, ChildVirtualPath: null, ChildProbe: null,
                Failure: WorkerFailure.Cancelled);
            yield break;
        }

        if (_includeArchiveCorrupt)
        {
            yield return new WorkerJobResult(
                item.JobId, item.FileId, WorkerResultKind.Gap,
                Chunk: null,
                Gap: new CoverageGap(
                    GapId: Guid.NewGuid(),
                    ScanId: item.ScanId,
                    FileId: item.FileId,
                    VirtualPath: item.VirtualPath,
                    FormatId: item.FormatHint,
                    Stage: "parse",
                    Reason: GapReason.Corrupt,
                    DetailCode: "archive_corrupt",
                    PlannedBytes: item.DeclaredLength,
                    ProcessedBytes: 0,
                    CreatedAtUtc: DateTimeOffset.UtcNow),
                ChildVirtualPath: null, ChildProbe: null, Failure: null);
        }

        string text = ReadFileText(item.VirtualPath);

        var chunk = new ContentChunk(
            ProtocolVersion: 1,
            JobId: item.JobId,
            Sequence: 0,
            VirtualPath: item.VirtualPath,
            FormatId: item.FormatHint,
            ContentKind: ContentKind.Text,
            Encoding: null,
            Text: text,
            SourceStart: 0,
            SourceLength: text.Length,
            LocationMap: Array.Empty<LocationMapEntry>(),
            IsFinal: true);

        yield return new WorkerJobResult(
            item.JobId, item.FileId, WorkerResultKind.Chunk,
            Chunk: chunk, Gap: null, ChildVirtualPath: null, ChildProbe: null, Failure: null);

        if (_mutateTwice is not null && string.Equals(item.VirtualPath,
                Path.GetFileName(_mutateTwice), StringComparison.OrdinalIgnoreCase))
        {
            yield return new WorkerJobResult(
                item.JobId, item.FileId, WorkerResultKind.Gap,
                Chunk: null,
                Gap: new CoverageGap(
                    GapId: Guid.NewGuid(),
                    ScanId: item.ScanId,
                    FileId: item.FileId,
                    VirtualPath: item.VirtualPath,
                    FormatId: item.FormatHint,
                    Stage: "parse",
                    Reason: GapReason.FileUnstable,
                    DetailCode: "file_unstable",
                    PlannedBytes: item.DeclaredLength,
                    ProcessedBytes: 0,
                    CreatedAtUtc: DateTimeOffset.UtcNow),
                ChildVirtualPath: null, ChildProbe: null, Failure: null);
        }

        yield return new WorkerJobResult(
            item.JobId, item.FileId, WorkerResultKind.Completed,
            Chunk: null, Gap: null, ChildVirtualPath: null, ChildProbe: null, Failure: null);

        await Task.CompletedTask;
    }

    private string ReadFileText(string virtualPath)
    {
        if (_root is null)
        {
            return string.Empty;
        }
        try
        {
            return File.ReadAllText(Path.Combine(_root.FullName, virtualPath));
        }
        catch
        {
            return string.Empty;
        }
    }

    private static async Task MutateFile(string path, string content)
    {
        try
        {
            await using FileStream writer = new(path, FileMode.Open, FileAccess.Write, FileShare.None);
            writer.Position = 0;
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(content);
            await writer.WriteAsync(bytes);
            await writer.FlushAsync();
        }
        catch
        {
            // ignore — file may be locked
        }
    }
}
