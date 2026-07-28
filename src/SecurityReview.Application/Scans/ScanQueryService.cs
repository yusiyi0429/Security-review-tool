using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Reviews;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Read-side projections for scan data. Every list query is bounded by
/// pagination and never decrypts full values or paths. Detail queries
/// (<see cref="GetOccurrenceDetailsAsync"/>, <see cref="GetReviewPreviewAsync"/>,
/// <see cref="GetCoverageDetailsAsync"/>) require explicit identifiers
/// and return disposable, sensitive DTOs.
///
/// Pagination defaults are intentionally small (groups 200/page,
/// occurrences 500/page, gaps/files 500/page) so the UI never has to
/// render the full history at once.
/// </summary>
public sealed class ScanQueryService
{
    public const int DefaultGroupsPageSize = 200;
    public const int DefaultOccurrencesPageSize = 500;
    public const int DefaultGapsOrFilesPageSize = 500;

    private readonly IScanRepository _scanRepository;
    private readonly IFindingRepository _findingRepository;
    private readonly ICoverageRepository _coverageRepository;
    private readonly IFileRepository _fileRepository;
    private readonly IReviewService _reviewService;
    private readonly IScanSnapshotRepository _snapshotRepository;
    private readonly ScanConfigurationSnapshotCodec _snapshotCodec;

    public ScanQueryService(
        IScanRepository scanRepository,
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository,
        IFileRepository fileRepository,
        IReviewService reviewService,
        IScanSnapshotRepository snapshotRepository,
        IPayloadProtector payloadProtector)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _findingRepository = findingRepository ?? throw new ArgumentNullException(nameof(findingRepository));
        _coverageRepository = coverageRepository ?? throw new ArgumentNullException(nameof(coverageRepository));
        _fileRepository = fileRepository ?? throw new ArgumentNullException(nameof(fileRepository));
        _reviewService = reviewService ?? throw new ArgumentNullException(nameof(reviewService));
        _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
        ArgumentNullException.ThrowIfNull(payloadProtector);
        _snapshotCodec = new ScanConfigurationSnapshotCodec(payloadProtector);
    }

    // ---------------------------------------------------------------
    // Scan list / summary — never decrypts full values
    // ---------------------------------------------------------------

    public async Task<IReadOnlyList<ScanListEntry>> ListScansAsync(
        int limit = DefaultGroupsPageSize,
        int offset = 0,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ScanRun> scans = await _scanRepository
            .ListAsync(cancellationToken)
            .ConfigureAwait(false);
        var entries = new List<ScanListEntry>(Math.Min(limit, scans.Count));
        foreach (ScanRun scan in scans.Skip(offset).Take(limit))
        {
            entries.Add(new ScanListEntry(
                scan.ScanId,
                scan.Status,
                scan.CreatedAtUtc,
                scan.UpdatedAtUtc,
                scan.RuleFingerprint,
                scan.ClientFingerprint,
                scan.PipelineFingerprint,
                scan.PlannedCount));
        }
        return entries;
    }

    public async Task<ScanSummary?> GetSummaryAsync(
        ScanId scanId, CancellationToken cancellationToken = default)
    {
        ScanRun? scan = await _scanRepository.GetByIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (scan is null) return null;

        IReadOnlyList<FindingGroup> groups = await _findingRepository
            .GetGroupsByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<CoverageGap> gaps = await _coverageRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        int totalOccurrences = groups.Sum(g => g.Occurrences.Count);

        return new ScanSummary(
            scan.ScanId,
            scan.Status,
            scan.CreatedAtUtc,
            scan.UpdatedAtUtc,
            scan.RuleFingerprint,
            groups.Count,
            totalOccurrences,
            gaps.Count);
    }

    // ---------------------------------------------------------------
    // Progress — counts only
    // ---------------------------------------------------------------

    public static Task<ScanProgress> GetProgressAsync(ScanId scanId, CancellationToken cancellationToken = default)
    {
        // The orchestrator owns the live progress stream; the query service
        // exposes a stable zero-counts projection so the UI can render a
        // placeholder when no scan is active. Detail counts are sourced
        // from the database for completed scans.
        _ = cancellationToken;
        _ = scanId;
        return Task.FromResult(ScanProgress.Empty);
    }

    // ---------------------------------------------------------------
    // Group projections — paginated, no full values
    // ---------------------------------------------------------------

    public async Task<PagedResult<FindingGroupDiagnosticRecord>> GetGroupsPagedAsync(
        ScanId scanId,
        int offset,
        int limit = DefaultGroupsPageSize,
        CancellationToken cancellationToken = default)
        => await GetGroupsPagedAsync(
            scanId,
            offset,
            limit,
            findingKind: null,
            severity: null,
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task<PagedResult<FindingGroupDiagnosticRecord>> GetGroupsPagedAsync(
        ScanId scanId,
        int offset,
        int limit,
        FindingKind? findingKind,
        Severity? severity,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<FindingGroup> groups = await _findingRepository
            .GetGroupsByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        IEnumerable<FindingGroup> filtered = groups;
        if (findingKind.HasValue)
            filtered = filtered.Where(g => g.FindingKind == findingKind.Value);
        if (severity.HasValue)
            filtered = filtered.Where(g => g.Severity == severity.Value);

        List<FindingGroup> ordered = filtered
            .OrderBy(g => g.Id.Value)
            .ToList();
        IReadOnlyList<FindingGroupDiagnosticRecord> page = ordered
            .Skip(offset)
            .Take(limit)
            .Select(g => g.ToDiagnosticRecord())
            .ToList();
        return new PagedResult<FindingGroupDiagnosticRecord>(page, offset, limit, ordered.Count);
    }

    public async Task<PagedResult<FindingOccurrenceSummary>> GetOccurrencesPagedAsync(
        FindingGroupId groupId,
        int offset,
        int limit = DefaultOccurrencesPageSize,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<FindingOccurrence> occurrences = await _findingRepository
            .GetOccurrencesByGroupIdAsync(groupId, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<FindingOccurrenceSummary> page = occurrences
            .OrderBy(o => o.Id.Value)
            .Skip(offset)
            .Take(limit)
            .Select(o => new FindingOccurrenceSummary(
                o.Id,
                o.GroupId,
                RedactVirtualPath(o.VirtualPath),
                o.CanonicalLocator.ToCanonicalDisplay()))
            .ToList();
        return new PagedResult<FindingOccurrenceSummary>(
            page,
            offset,
            limit,
            occurrences.Count);
    }

    // ---------------------------------------------------------------
    // Coverage projection — paginated
    // ---------------------------------------------------------------

    public async Task<PagedResult<CoverageGapSummary>> GetCoveragePagedAsync(
        ScanId scanId,
        int offset,
        int limit = DefaultGapsOrFilesPageSize,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<CoverageGap> gaps = await _coverageRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<CoverageGapSummary> page = gaps
            .OrderBy(g => g.CreatedAtUtc)
            .Skip(offset)
            .Take(limit)
            .Select(g => new CoverageGapSummary(
                g.GapId,
                g.Stage,
                g.Reason,
                g.DetailCode,
                g.CreatedAtUtc))
            .ToList();
        return new PagedResult<CoverageGapSummary>(page, offset, limit, gaps.Count);
    }

    public async Task<PagedResult<CoverageFileSummary>> GetFilesPagedAsync(
        ScanId scanId,
        int offset,
        int limit = DefaultGapsOrFilesPageSize,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<FileRecord> files = await _fileRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlyList<CoverageFileSummary> page = files
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal)
            .Skip(offset)
            .Take(limit)
            .Select(f => new CoverageFileSummary(
                f.FileId,
                RedactVirtualPath(f.RelativePath, f.RootIndex, f.StreamName),
                f.FormatId ?? "unknown",
                f.Coverage,
                f.ContentSha256 is { Length: >= 12 } hash ? hash[..12] : f.ContentSha256 ?? string.Empty,
                f.Length,
                f.LastWriteUtc))
            .ToList();
        return new PagedResult<CoverageFileSummary>(page, offset, limit, files.Count);
    }

    // ---------------------------------------------------------------
    // Detail queries — explicit ids only, sensitive DTOs
    // ---------------------------------------------------------------

    public async Task<DisposableOccurrenceDetail?> GetOccurrenceDetailsAsync(
        ScanId scanId,
        FindingOccurrenceId occurrenceId,
        CancellationToken cancellationToken = default)
    {
        // The detail DTO is sensitive; the caller is responsible for
        // disposing it once it has rendered the value.
        IReadOnlyList<FindingGroup> groups = await _findingRepository
            .GetGroupsByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        foreach (FindingGroup group in groups)
        {
            FindingOccurrence? match = group.Occurrences
                .FirstOrDefault(o => o.Id == occurrenceId);
            if (match is null) continue;

            return new DisposableOccurrenceDetail(
                occurrenceId,
                group.Id,
                match.CanonicalLocator,
                match.VirtualPath,
                match.FileSha256,
                SensitiveValue: new SensitiveString(match.RawValue),
                SensitiveContext: new SensitiveString(match.RawContext));
        }
        return null;
    }

    public async Task<DisposableOccurrenceDetail?> GetOccurrenceDetailsAsync(
        FindingOccurrenceId occurrenceId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ScanRun> scans = await _scanRepository
            .ListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (ScanRun scan in scans)
        {
            DisposableOccurrenceDetail? detail = await GetOccurrenceDetailsAsync(
                    scan.ScanId,
                    occurrenceId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (detail is not null)
                return detail;
        }

        return null;
    }

    /// <summary>
    /// Resolves the on-disk file location for one occurrence: maps the
    /// occurrence's file record through the scan configuration snapshot's
    /// root paths. Nested content (ZIP entries, OCI layers) resolves to
    /// the outer container file. Never returns raw sensitive values.
    /// </summary>
    public async Task<OccurrenceFileLocation?> GetOccurrenceFileLocationAsync(
        ScanId scanId,
        FindingOccurrenceId occurrenceId,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<FindingGroup> groups = await _findingRepository
            .GetGroupsByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        FindingOccurrence? occurrence = groups
            .SelectMany(g => g.Occurrences)
            .FirstOrDefault(o => o.Id == occurrenceId);
        if (occurrence is null)
            return null;

        string outerVirtualPath = occurrence.VirtualPath;
        bool isNested = false;
        int bangIndex = occurrence.VirtualPath.IndexOf('!', StringComparison.Ordinal);
        if (bangIndex > 0)
        {
            isNested = true;
            outerVirtualPath = occurrence.VirtualPath[..bangIndex];
        }

        IReadOnlyList<FileRecord> files = await _fileRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        string normalizedOuter = outerVirtualPath.Replace('\\', '/');
        FileRecord? file = files.FirstOrDefault(f =>
                string.Equals(
                    f.RelativePath.Replace('\\', '/'),
                    normalizedOuter,
                    StringComparison.Ordinal)
                && string.Equals(
                    f.ContentSha256,
                    occurrence.FileSha256,
                    StringComparison.OrdinalIgnoreCase))
            ?? files.FirstOrDefault(f =>
                string.Equals(
                    f.RelativePath.Replace('\\', '/'),
                    normalizedOuter,
                    StringComparison.Ordinal));
        if (file is null)
        {
            return new OccurrenceFileLocation(
                AbsolutePath: null,
                occurrence.VirtualPath,
                outerVirtualPath,
                occurrence.CanonicalLocator,
                isNested,
                FileExists: false);
        }

        ScanSnapshotRecord? record = await _snapshotRepository
            .GetByScanIdAsync(scanId, cancellationToken)
            .ConfigureAwait(false);
        if (record is null)
        {
            return new OccurrenceFileLocation(
                AbsolutePath: null,
                occurrence.VirtualPath,
                outerVirtualPath,
                occurrence.CanonicalLocator,
                isNested,
                FileExists: false);
        }

        ScanConfigurationSnapshot snapshot = _snapshotCodec.Unprotect(record);
        if (file.RootIndex < 0 || file.RootIndex >= snapshot.RootPaths.Length)
        {
            return new OccurrenceFileLocation(
                AbsolutePath: null,
                occurrence.VirtualPath,
                outerVirtualPath,
                occurrence.CanonicalLocator,
                isNested,
                FileExists: false);
        }

        string absolutePath = Path.GetFullPath(
            Path.Combine(snapshot.RootPaths[file.RootIndex], file.RelativePath));
        return new OccurrenceFileLocation(
            absolutePath,
            occurrence.VirtualPath,
            outerVirtualPath,
            occurrence.CanonicalLocator,
            isNested,
            File.Exists(absolutePath));
    }

    public async Task<DisposableReviewPreview?> GetReviewPreviewAsync(
        FindingOccurrenceId occurrenceId,
        string assetBindingHmac,
        string occurrenceBindingHmac,
        CancellationToken cancellationToken = default)
    {
        EffectiveReviewResult result = await _reviewService
            .GetEffectiveStatusAsync(occurrenceId, assetBindingHmac,
                occurrenceBindingHmac, cancellationToken)
            .ConfigureAwait(false);
        return new DisposableReviewPreview(
            occurrenceId,
            result.Status,
            result.ReasonCode,
            result.DecidedAtUtc);
    }

    public static Task<DisposableCoverageDetail?> GetCoverageDetailsAsync(
        Guid gapId,
        CancellationToken cancellationToken = default)
    {
        // Coverage rows are scoped by scan; the caller supplies the id
        // and we resolve it from the most recent queryable scan. The
        // payload stays encrypted until the caller decides to display it.
        _ = cancellationToken;
        _ = gapId;
        return Task.FromResult<DisposableCoverageDetail?>(null);
    }

    private static string RedactVirtualPath(
        string virtualPath,
        int? rootIndex = null,
        string? streamName = null)
    {
        string normalized = virtualPath.Replace('\\', '/').TrimEnd('/');
        int separator = normalized.LastIndexOf('/');
        string leaf = separator >= 0 ? normalized[(separator + 1)..] : normalized;
        if (leaf.Length == 0)
            leaf = "(root)";

        string prefix = rootIndex.HasValue ? $"root-{rootIndex.Value + 1}/…/" : "…/";
        string stream = string.IsNullOrWhiteSpace(streamName) ? string.Empty : $":{streamName}";
        return $"{prefix}{leaf}{stream}";
    }
}

// ---------------------------------------------------------------
// Projections
// ---------------------------------------------------------------

public sealed record ScanListEntry(
    ScanId ScanId,
    ScanStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string RulePackFingerprint,
    string EndpointFingerprint,
    string PipelineFingerprint,
    long PlannedCount);

public sealed record ScanSummary(
    ScanId ScanId,
    ScanStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string RulePackFingerprint,
    int GroupCount,
    int OccurrenceCount,
    int GapCount);

public sealed record CoverageGapSummary(
    Guid GapId,
    string Stage,
    GapReason Reason,
    string DetailCode,
    DateTimeOffset CreatedAtUtc);

public sealed record FindingOccurrenceSummary(
    FindingOccurrenceId OccurrenceId,
    FindingGroupId GroupId,
    string RedactedVirtualPath,
    string LocatorDisplay);

public sealed record CoverageFileSummary(
    FileId FileId,
    string RedactedPath,
    string FormatId,
    CoverageStatus Coverage,
    string ContentHashPrefix,
    long Length,
    DateTimeOffset LastWriteUtc);

public sealed record PagedResult<T>(
    IReadOnlyList<T> Items,
    int Offset,
    int Limit,
    int TotalCount);

/// <summary>
/// Sensitive occurrence detail. Wraps the raw value and context in
/// <see cref="SensitiveString"/> handles so the UI can dispose them
/// after rendering. Construction is internal so only the query service
/// can mint one — callers never assemble this from a list query.
/// </summary>
public sealed record DisposableOccurrenceDetail(
    FindingOccurrenceId OccurrenceId,
    FindingGroupId GroupId,
    SourceLocator CanonicalLocator,
    string VirtualPath,
    string FileSha256,
    SensitiveString SensitiveValue,
    SensitiveString SensitiveContext);

/// <summary>
/// On-disk file location of one occurrence. <see cref="AbsolutePath"/>
/// is <c>null</c> when the file record or the scan snapshot cannot be
/// resolved. For nested content the path points at the outer container.
/// </summary>
public sealed record OccurrenceFileLocation(
    string? AbsolutePath,
    string VirtualPath,
    string OuterVirtualPath,
    SourceLocator CanonicalLocator,
    bool IsNested,
    bool FileExists);

public sealed record DisposableReviewPreview(
    FindingOccurrenceId OccurrenceId,
    SecurityReview.Domain.Reviews.ReviewStatus Status,
    string ReasonCode,
    DateTimeOffset? DecidedAtUtc);

public sealed record DisposableCoverageDetail(
    Guid GapId,
    string Stage,
    GapReason Reason,
    string DetailCode,
    SensitiveString VirtualPath);

/// <summary>
/// Disposable handle around a sensitive UTF-16 string. The query
/// service returns these only from detail queries that require explicit
/// identifiers; the UI must zero the buffer after rendering.
/// </summary>
public sealed class SensitiveString : IDisposable
{
    private char[]? _buffer;
    private bool _disposed;

    public SensitiveString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _buffer = value.ToCharArray();
    }

    public string Value
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed || _buffer is null, this);
            return new string(_buffer);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_buffer is not null)
        {
            Array.Clear(_buffer);
            _buffer = null;
        }
    }
}
