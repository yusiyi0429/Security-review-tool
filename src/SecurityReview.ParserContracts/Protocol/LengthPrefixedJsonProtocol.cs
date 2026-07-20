using System.Buffers.Binary;
using System.Text.Json;

namespace SecurityReview.ParserContracts.Protocol;

public static class LengthPrefixedJsonProtocol
{
    public static async Task WriteAsync(Stream stream, ProtocolEnvelope message, CancellationToken cancellationToken)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(message, ProtocolJsonContext.Default.ProtocolEnvelope);
        if (payload.Length > ProtocolConstants.MaxFrameBytes) throw new ProtocolException("Frame exceeds the protocol limit.");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<ProtocolEnvelope> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        (ProtocolEnvelope message, _) = await ReadWithRawAsync(stream, cancellationToken).ConfigureAwait(false);
        return message;
    }

    // Returns the parsed message together with the exact frame bytes so callers
    // can feed the canonical frame to ProtocolSessionValidator.
    public static async Task<(ProtocolEnvelope Message, byte[] CanonicalFrame)> ReadWithRawAsync(
        Stream stream, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > ProtocolConstants.MaxFrameBytes) throw new ProtocolException("Invalid frame length.");
        byte[] payload = GC.AllocateUninitializedArray<byte>(length);
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        ProtocolEnvelope? message;
        try
        {
            message = JsonSerializer.Deserialize(payload, ProtocolJsonContext.Default.ProtocolEnvelope);
        }
        catch (JsonException ex)
        {
            throw new ProtocolException("Frame JSON is invalid.", ex);
        }

        if (message is null) throw new ProtocolException("Frame JSON is null.");
        if (message.ProtocolVersion != ProtocolConstants.Version) throw new ProtocolException("Protocol version mismatch.");
        return (message, payload);
    }
}
