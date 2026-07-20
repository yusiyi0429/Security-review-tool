using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Domain;

namespace SecurityReview.ParserContracts.Protocol;

public enum SessionVerdict { Accept, IgnoreDuplicate, TerminateJob }

public sealed class ProtocolSessionValidator
{
    public const int NonceLength = 32;

    private readonly ScanId _expectedScanId;
    private readonly JobId _expectedJobId;
    private readonly byte[] _expectedNonce;
    private readonly string _expectedWorkerBuildSha256;
    private bool _handshakeComplete;
    private bool _completed;
    private long _lastSequence = -1;
    private byte[]? _lastFrameDigest;

    public ProtocolSessionValidator(ScanId expectedScanId, JobId expectedJobId,
        ReadOnlySpan<byte> expectedNonce, string expectedWorkerBuildSha256)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedWorkerBuildSha256);
        if (expectedNonce.Length != NonceLength)
        {
            throw new ArgumentException($"Nonce must be {NonceLength} bytes.", nameof(expectedNonce));
        }

        _expectedScanId = expectedScanId;
        _expectedJobId = expectedJobId;
        _expectedNonce = expectedNonce.ToArray();
        _expectedWorkerBuildSha256 = expectedWorkerBuildSha256;
    }

    public SessionVerdict Validate(ProtocolEnvelope message, ReadOnlySpan<byte> canonicalFrame)
    {
        if (_completed) return SessionVerdict.TerminateJob;
        if (message.Sequence < 0) return SessionVerdict.TerminateJob;
        if (message.Sequence == _lastSequence && _lastFrameDigest is not null)
        {
            byte[] digest = SHA256.HashData(canonicalFrame);
            return CryptographicOperations.FixedTimeEquals(digest, _lastFrameDigest)
                ? SessionVerdict.IgnoreDuplicate
                : SessionVerdict.TerminateJob;
        }

        if (message.Sequence != _lastSequence + 1) return SessionVerdict.TerminateJob;
        if (!ValidateSemantics(message)) return SessionVerdict.TerminateJob;
        _lastSequence = message.Sequence;
        _lastFrameDigest = SHA256.HashData(canonicalFrame);
        return SessionVerdict.Accept;
    }

    private bool ValidateSemantics(ProtocolEnvelope message)
    {
        if (!_handshakeComplete)
        {
            return message.MessageType == MessageType.Hello && ValidateHello(message);
        }

        switch (message.MessageType)
        {
            case MessageType.Hello:
                return false;
            case MessageType.HelloAccepted:
                return message.ScanId is null && message.JobId is null;
            case MessageType.Heartbeat:
                return (message.ScanId is null && message.JobId is null) || IdsMatch(message);
            case MessageType.ParseJob:
            case MessageType.ContentChunk:
            case MessageType.GapProduced:
                return IdsMatch(message);
            case MessageType.ParseCompleted:
            case MessageType.ParseFailed:
            case MessageType.CancelJob:
                if (!IdsMatch(message)) return false;
                _completed = true;
                return true;
            default:
                return false;
        }
    }

    private bool IdsMatch(ProtocolEnvelope message) =>
        message.ScanId == _expectedScanId && message.JobId == _expectedJobId;

    private bool ValidateHello(ProtocolEnvelope message)
    {
        if (message.ScanId is not null || message.JobId is not null) return false;
        HelloPayload? hello;
        try
        {
            hello = JsonSerializer.Deserialize(message.PayloadJson, ProtocolJsonContext.Default.HelloPayload);
        }
        catch (JsonException)
        {
            return false;
        }

        if (hello is null) return false;
        byte[] nonce;
        try
        {
            nonce = Convert.FromBase64String(hello.Nonce);
        }
        catch (FormatException)
        {
            return false;
        }

        if (nonce.Length != NonceLength) return false;
        if (!CryptographicOperations.FixedTimeEquals(nonce, _expectedNonce)) return false;
        if (!string.Equals(hello.WorkerBuildSha256, _expectedWorkerBuildSha256, StringComparison.Ordinal)) return false;
        _handshakeComplete = true;
        return true;
    }
}

public sealed record HelloPayload(string Nonce, string WorkerBuildSha256);
