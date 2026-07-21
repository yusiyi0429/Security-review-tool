using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Tracks coverage of every unit (file stream, metadata unit, archive child)
/// during a scan. Units are registered as planned before work begins and
/// transition exactly once to a terminal <see cref="CoverageStatus"/>.
/// Duplicate terminal transitions throw. Final reconciliation validates that
/// every planned unit reached a terminal state.
/// </summary>
public interface ICoverageLedger
{
    ScanId ScanId { get; }

    /// <summary>Register a file stream as planned for coverage tracking.</summary>
    void RegisterFile(FileId fileId, long plannedBytes);

    /// <summary>Register an inventory metadata unit as planned.</summary>
    void RegisterMetadata(InventoryMetadataUnit unit);

    /// <summary>Register an archive child entry as planned.</summary>
    void RegisterChild(FileId parentFileId, string virtualPath, long plannedBytes);

    /// <summary>Transition a file to a terminal coverage status.</summary>
    void TransitionFile(FileId fileId, CoverageStatus status);

    /// <summary>Transition a metadata unit to a terminal coverage status.</summary>
    void TransitionMetadata(InventoryMetadataUnit unit, CoverageStatus status);

    /// <summary>Transition an archive child to a terminal coverage status.</summary>
    void TransitionChild(string virtualPath, CoverageStatus status);

    /// <summary>Record a coverage gap for a file.</summary>
    void AddGap(CoverageGap gap);

    /// <summary>
    /// Compare planned IDs to terminal IDs. Returns the reconciled summary.
    /// Throws if any unit is still Planned (not transitioned).
    /// </summary>
    CoverageSummary Reconcile();
}
