using SecurityReview.Domain;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Core;

/// <summary>
/// Context carried through a single parse operation. Provides the job
/// identity, virtual path, resource limits, and cancellation support.
/// </summary>
public sealed record ParseContext(
    JobId JobId,
    ScanId ScanId,
    string VirtualPath,
    ParseLimits Limits);
