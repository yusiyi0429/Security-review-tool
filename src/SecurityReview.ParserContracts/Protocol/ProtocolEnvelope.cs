using SecurityReview.Domain;

namespace SecurityReview.ParserContracts.Protocol;

public sealed record ProtocolEnvelope(int ProtocolVersion, MessageType MessageType,
    Guid CorrelationId, ScanId? ScanId, JobId? JobId, long Sequence,
    DateTimeOffset SentAtUtc, string PayloadJson)
{
    public static ProtocolEnvelope Create(MessageType type, Guid correlationId, string payloadJson,
        ScanId? scanId = null, JobId? jobId = null) =>
        new(ProtocolConstants.Version, type, correlationId, scanId, jobId, 0,
            DateTimeOffset.UnixEpoch, payloadJson);
}
