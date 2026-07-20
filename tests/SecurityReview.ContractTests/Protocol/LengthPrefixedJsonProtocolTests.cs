using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.ContractTests.Protocol;

public sealed class LengthPrefixedJsonProtocolTests
{
    [Fact]
    public async Task Round_trips_a_valid_envelope()
    {
        var expected = ProtocolEnvelope.Create(MessageType.Heartbeat, Guid.Parse("11111111-1111-1111-1111-111111111111"), "{}");
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, expected, TestContext.Current.CancellationToken);
        stream.Position = 0;
        ProtocolEnvelope actual = await LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task Rejects_frame_larger_than_one_mebibyte()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(BitConverter.GetBytes(ProtocolConstants.MaxFrameBytes + 1), TestContext.Current.CancellationToken);
        stream.Position = 0;
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Rejects_truncated_payload()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(BitConverter.GetBytes(12), TestContext.Current.CancellationToken);
        await stream.WriteAsync("{}"u8.ToArray(), TestContext.Current.CancellationToken);
        stream.Position = 0;
        await Assert.ThrowsAsync<EndOfStreamException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Rejects_unknown_json_members()
    {
        await using var stream = new MemoryStream();
        byte[] payload = "{\"protocolVersion\":1,\"messageType\":8,\"correlationId\":\"11111111-1111-1111-1111-111111111111\",\"scanId\":null,\"jobId\":null,\"sequence\":0,\"sentAtUtc\":\"1970-01-01T00:00:00+00:00\",\"payloadJson\":\"{}\",\"unexpectedMember\":true}"u8.ToArray();
        await stream.WriteAsync(BitConverter.GetBytes(payload.Length), TestContext.Current.CancellationToken);
        await stream.WriteAsync(payload, TestContext.Current.CancellationToken);
        stream.Position = 0;
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Rejects_protocol_version_mismatch()
    {
        var message = new ProtocolEnvelope(2, MessageType.Heartbeat, Guid.NewGuid(), null, null, 0, DateTimeOffset.UnixEpoch, "{}");
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, message, TestContext.Current.CancellationToken);
        stream.Position = 0;
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Rejects_zero_and_negative_frame_lengths()
    {
        foreach (int length in new[] { 0, -1, int.MinValue })
        {
            await using var stream = new MemoryStream();
            await stream.WriteAsync(BitConverter.GetBytes(length), TestContext.Current.CancellationToken);
            stream.Position = 0;
            await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task Write_rejects_envelope_larger_than_one_mebibyte()
    {
        var message = ProtocolEnvelope.Create(MessageType.ContentChunk, Guid.NewGuid(), new string('x', ProtocolConstants.MaxFrameBytes));
        await using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.WriteAsync(stream, message, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Oversized_frame_header_does_not_trigger_large_allocation()
    {
        await using var stream = new MemoryStream();
        await stream.WriteAsync(BitConverter.GetBytes(int.MaxValue), TestContext.Current.CancellationToken);
        stream.Position = 0;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        await Assert.ThrowsAsync<ProtocolException>(() => LengthPrefixedJsonProtocol.ReadAsync(stream, TestContext.Current.CancellationToken));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Assert.True(allocated < 65_536, $"Expected bounded allocation, got {allocated} bytes.");
    }

    [Fact]
    public async Task Fuzz_random_bytes_only_throw_protocol_or_end_of_stream()
    {
        var random = new Random(0x5EED11);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        for (int iteration = 0; iteration < 512; iteration++)
        {
            int length = random.Next(0, (2 * 1024 * 1024) + 1);
            byte[] bytes = new byte[length];
            random.NextBytes(bytes);
            if (length >= 4 && iteration % 3 == 0)
            {
                int declared = random.Next(-2, ProtocolConstants.MaxFrameBytes * 2);
                BitConverter.GetBytes(declared).CopyTo(bytes, 0);
            }

            await using var stream = new MemoryStream(bytes);
            try
            {
                _ = await LengthPrefixedJsonProtocol.ReadAsync(stream, timeout.Token);
            }
            catch (Exception ex) when (ex is ProtocolException or EndOfStreamException)
            {
            }
        }
    }

    [Fact]
    public async Task Fuzz_valid_frames_with_random_truncation_behave()
    {
        var random = new Random(0xC0FFEE);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        for (int iteration = 0; iteration < 128; iteration++)
        {
            var expected = ProtocolEnvelope.Create(MessageType.ContentChunk, Guid.NewGuid(), new string('中', random.Next(0, 4096)));
            await using var buffer = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(buffer, expected, TestContext.Current.CancellationToken);
            byte[] frame = buffer.ToArray();
            int keep = random.Next(0, frame.Length + 1);
            await using var stream = new MemoryStream(frame, 0, keep);
            try
            {
                ProtocolEnvelope actual = await LengthPrefixedJsonProtocol.ReadAsync(stream, timeout.Token);
                Assert.Equal(frame.Length, keep);
                Assert.Equal(expected, actual);
            }
            catch (Exception ex) when (ex is ProtocolException or EndOfStreamException)
            {
                Assert.True(keep < frame.Length);
            }
        }
    }
}
