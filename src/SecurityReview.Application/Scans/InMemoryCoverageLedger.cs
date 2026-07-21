using System.Collections.Concurrent;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// In-memory implementation of <see cref="ICoverageLedger"/>. Thread-safe.
/// All units must be registered before any transitions. Each unit transitions
/// exactly once from Planned to a terminal status. Duplicate terminal
/// transitions throw. Final reconciliation fails if any unit is still Planned.
/// </summary>
public sealed class InMemoryCoverageLedger : ICoverageLedger
{
    private enum UnitState { Planned, Covered, PartiallyCovered, NotCovered }

    private sealed class FileEntry
    {
        public UnitState State = UnitState.Planned;
        public long PlannedBytes;
    }

    private readonly ConcurrentDictionary<FileId, FileEntry> _files = new();
    private readonly ConcurrentDictionary<InventoryMetadataUnit, FileEntry> _metadata = new();
    private readonly ConcurrentDictionary<string, FileEntry> _children = new();
    private readonly ConcurrentBag<CoverageGap> _gaps = new();

    public InMemoryCoverageLedger(ScanId scanId)
    {
        ScanId = scanId;
    }

    public ScanId ScanId { get; }

    public void RegisterFile(FileId fileId, long plannedBytes)
    {
        if (!_files.TryAdd(fileId, new FileEntry { PlannedBytes = plannedBytes }))
        {
            throw new InvalidOperationException(
                $"File {fileId.Value} is already registered in the coverage ledger.");
        }
    }

    public void RegisterMetadata(InventoryMetadataUnit unit)
    {
        if (!_metadata.TryAdd(unit, new FileEntry { PlannedBytes = unit.Value.Length }))
        {
            throw new InvalidOperationException(
                $"Metadata unit {unit.Kind}:{unit.Value} is already registered.");
        }
    }

    public void RegisterChild(FileId parentFileId, string virtualPath, long plannedBytes)
    {
        if (!_children.TryAdd(virtualPath, new FileEntry { PlannedBytes = plannedBytes }))
        {
            throw new InvalidOperationException(
                $"Child {virtualPath} is already registered in the coverage ledger.");
        }
    }

    public void TransitionFile(FileId fileId, CoverageStatus status)
    {
        if (!_files.TryGetValue(fileId, out FileEntry? entry))
        {
            throw new InvalidOperationException(
                $"File {fileId.Value} was not registered in the coverage ledger.");
        }

        TransitionEntry(entry, status, () => $"File {fileId.Value}");
    }

    public void TransitionMetadata(InventoryMetadataUnit unit, CoverageStatus status)
    {
        if (!_metadata.TryGetValue(unit, out FileEntry? entry))
        {
            throw new InvalidOperationException(
                $"Metadata unit {unit.Kind}:{unit.Value} was not registered.");
        }

        TransitionEntry(entry, status, () => $"Metadata {unit.Kind}:{unit.Value}");
    }

    public void TransitionChild(string virtualPath, CoverageStatus status)
    {
        if (!_children.TryGetValue(virtualPath, out FileEntry? entry))
        {
            throw new InvalidOperationException(
                $"Child {virtualPath} was not registered in the coverage ledger.");
        }

        TransitionEntry(entry, status, () => $"Child {virtualPath}");
    }

    public void AddGap(CoverageGap gap)
    {
        _gaps.Add(gap);
    }

    public CoverageSummary Reconcile()
    {
        int plannedUnits = _files.Count + _metadata.Count + _children.Count;
        int coveredUnits = 0;
        var gaps = new List<CoverageGap>(_gaps);

        // Check file entries
        foreach ((FileId fileId, FileEntry entry) in _files)
        {
            switch (entry.State)
            {
                case UnitState.Planned:
                    throw new InvalidOperationException(
                        $"Coverage reconciliation failed: file {fileId.Value} is still Planned.");
                case UnitState.Covered:
                    coveredUnits++;
                    break;
                case UnitState.PartiallyCovered:
                    break;
                case UnitState.NotCovered:
                    break;
            }
        }

        // Check metadata entries
        foreach ((InventoryMetadataUnit unit, FileEntry entry) in _metadata)
        {
            switch (entry.State)
            {
                case UnitState.Planned:
                    throw new InvalidOperationException(
                        $"Coverage reconciliation failed: metadata {unit.Kind}:{unit.Value} is still Planned.");
                case UnitState.Covered:
                    coveredUnits++;
                    break;
                case UnitState.PartiallyCovered:
                    break;
                case UnitState.NotCovered:
                    break;
            }
        }

        // Check child entries
        foreach ((string path, FileEntry entry) in _children)
        {
            switch (entry.State)
            {
                case UnitState.Planned:
                    throw new InvalidOperationException(
                        $"Coverage reconciliation failed: child {path} is still Planned.");
                case UnitState.Covered:
                    coveredUnits++;
                    break;
                case UnitState.PartiallyCovered:
                    break;
                case UnitState.NotCovered:
                    break;
            }
        }

        return CoverageSummary.Create(plannedUnits, coveredUnits, gaps.AsReadOnly());
    }

    private static void TransitionEntry(FileEntry entry, CoverageStatus status, Func<string> label)
    {
        UnitState targetState = status switch
        {
            CoverageStatus.Covered => UnitState.Covered,
            CoverageStatus.PartiallyCovered => UnitState.PartiallyCovered,
            CoverageStatus.NotCovered => UnitState.NotCovered,
            _ => throw new ArgumentOutOfRangeException(nameof(status), status,
                "Only terminal coverage statuses are allowed for transitions."),
        };

        UnitState original = Interlocked.CompareExchange(ref entry.State, targetState, UnitState.Planned);
        if (original != UnitState.Planned)
        {
            throw new InvalidOperationException(
                $"{label()} has already been transitioned from Planned to {original}.");
        }
    }
}
