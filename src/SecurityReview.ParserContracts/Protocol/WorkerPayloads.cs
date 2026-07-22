namespace SecurityReview.ParserContracts.Protocol;

/// <summary>Coverage-gap payload emitted by the sandbox worker.</summary>
public sealed record WorkerGapPayload(
    string Reason,
    string DetailCode,
    string? VirtualPath,
    string? FormatId,
    long? PlannedBytes,
    long? ProcessedBytes);

/// <summary>Metadata for a nested artifact discovered by an archive parser.</summary>
public sealed record WorkerChildPayload(
    string VirtualPath,
    string FormatId,
    double Confidence,
    long DeclaredLength);

/// <summary>Sanitized terminal failure returned by the sandbox worker.</summary>
public sealed record WorkerFailurePayload(string ErrorCode);
