namespace SecurityReview.Domain.Scans;

public enum GapReason
{
    UnsupportedFormat, UnsupportedRegion, AccessDenied, Encrypted, DecodeUnreliable,
    Corrupt, ArchiveLimit, ParserTimeout, ParserMemory, ParserCrash, SandboxUnavailable,
    FileUnstable, UserExcluded, LlmUnresolved, Cancelled, DiskFull, UnexpectedGitMetadata,
    ParserProtocolMismatch
}
