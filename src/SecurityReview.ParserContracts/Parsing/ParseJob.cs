using SecurityReview.Domain;

namespace SecurityReview.ParserContracts.Parsing;

public sealed record ParseJob(
    int ProtocolVersion,
    ScanId ScanId,
    JobId JobId,
    long InputHandle,
    long DeclaredLength,
    string FormatHint,
    string DisplayVirtualPath,
    ParseLimits Limits,
    IReadOnlyList<string> RequestedExtractors);
