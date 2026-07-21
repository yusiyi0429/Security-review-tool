namespace SecurityReview.Domain.Findings;

/// <summary>
/// A single concrete occurrence of a finding at one source location within
/// one file. Occurrences are grouped by value fingerprint across locations;
/// when the same location/rule pair appears from chunk overlap, they are
/// merged into one occurrence with multiple provenance entries.
///
/// Raw value and context are preserved here for immediate encryption/display,
/// but must NOT be exposed in diagnostic records.
/// </summary>
public sealed record FindingOccurrence(
    FindingOccurrenceId Id,
    FindingGroupId GroupId,
    string RawValue,
    string RawContext,
    SourceLocator CanonicalLocator,
    string VirtualPath,
    string FileSha256,
    IReadOnlyList<FindingProvenance> Provenance)
{
    /// <summary>
    /// Produces an identifier-only diagnostic record safe for reporting
    /// without leaking raw values.
    /// </summary>
    public OccurrenceDiagnosticRecord ToDiagnosticRecord() =>
        new(Id, GroupId);
}

/// <summary>
/// A sanitized view of an occurrence that exposes only identifiers —
/// suitable for aggregate reports and logs where raw values must not appear.
/// </summary>
public readonly record struct OccurrenceDiagnosticRecord(
    FindingOccurrenceId Id,
    FindingGroupId GroupId);
