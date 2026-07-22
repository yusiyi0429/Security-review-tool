namespace SecurityReview.ParserContracts.Protocol;

public enum MessageType
{
    Hello,
    HelloAccepted,
    ParseJob,
    ContentChunk,
    GapProduced,
    ParseCompleted,
    ParseFailed,
    CancelJob,
    Heartbeat,
    ChildDiscovered,
}
