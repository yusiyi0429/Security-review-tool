namespace SecurityReview.Domain;

public readonly record struct ScanId(Guid Value);
public readonly record struct FileId(Guid Value);
public readonly record struct JobId(Guid Value);
public readonly record struct CandidateId(Guid Value);
public readonly record struct FindingGroupId(Guid Value);
public readonly record struct FindingOccurrenceId(Guid Value);
public readonly record struct RuleId(string Value);
public readonly record struct DetectorId(string Value);
