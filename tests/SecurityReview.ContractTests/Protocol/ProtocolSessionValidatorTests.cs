using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.ContractTests.Protocol;

public sealed class ProtocolSessionValidatorTests
{
    private static readonly ScanId ExpectedScan = new(Guid.Parse("33333333-3333-3333-3333-333333333333"));
    private static readonly JobId ExpectedJob = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));
    private static readonly byte[] ExpectedNonce = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();
    private const string ExpectedBuildHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    private static ProtocolSessionValidator CreateValidator() =>
        new(ExpectedScan, ExpectedJob, ExpectedNonce, ExpectedBuildHash);

    private static string HelloPayloadJson(byte[]? nonce = null, string? buildHash = null) =>
        $"{{\"nonce\":\"{Convert.ToBase64String(nonce ?? ExpectedNonce)}\",\"workerBuildSha256\":\"{buildHash ?? ExpectedBuildHash}\"}}";

    private static ProtocolEnvelope Message(MessageType type, long sequence,
        ScanId? scan = null, JobId? job = null, string payloadJson = "{}") =>
        new(ProtocolConstants.Version, type, Guid.NewGuid(), scan, job, sequence,
            new DateTimeOffset(2026, 7, 20, 0, 0, 0, TimeSpan.Zero), payloadJson);

    private static ProtocolEnvelope Hello(long sequence = 0, byte[]? nonce = null, string? buildHash = null,
        ScanId? scan = null, JobId? job = null, string? rawPayload = null) =>
        Message(MessageType.Hello, sequence, scan, job, rawPayload ?? HelloPayloadJson(nonce, buildHash));

    private static byte[] Frame(ProtocolEnvelope envelope) =>
        JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJsonContext.Default.ProtocolEnvelope);

    private static SessionVerdict Validate(ProtocolSessionValidator validator, ProtocolEnvelope envelope) =>
        validator.Validate(envelope, Frame(envelope));

    private static ProtocolSessionValidator HandshakedValidator()
    {
        var validator = CreateValidator();
        ProtocolEnvelope hello = Hello();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, hello));
        return validator;
    }

    [Fact]
    public void Constructor_rejects_nonce_that_is_not_32_bytes()
    {
        Assert.Throws<ArgumentException>(() => new ProtocolSessionValidator(ExpectedScan, ExpectedJob, new byte[16], ExpectedBuildHash));
    }

    [Fact]
    public void Hello_with_matching_nonce_and_build_is_accepted()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Hello()));
    }

    [Fact]
    public void Pre_handshake_parse_job_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.ParseJob, 0, ExpectedScan, ExpectedJob)));
    }

    [Fact]
    public void Pre_handshake_heartbeat_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Message(MessageType.Heartbeat, 0)));
    }

    [Fact]
    public void Hello_with_wrong_nonce_is_terminated()
    {
        var validator = CreateValidator();
        byte[] wrongNonce = [.. ExpectedNonce];
        wrongNonce[0] ^= 0xFF;
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(nonce: wrongNonce)));
    }

    [Fact]
    public void Hello_with_nonce_that_is_not_32_bytes_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(nonce: new byte[16])));
    }

    [Fact]
    public void Hello_with_wrong_build_hash_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(buildHash: new string('0', 64))));
    }

    [Fact]
    public void Hello_with_malformed_payload_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(rawPayload: "not json")));
    }

    [Fact]
    public void Hello_with_unmapped_payload_member_is_terminated()
    {
        var validator = CreateValidator();
        string payload = $"{{\"nonce\":\"{Convert.ToBase64String(ExpectedNonce)}\",\"workerBuildSha256\":\"{ExpectedBuildHash}\",\"extra\":1}}";
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(rawPayload: payload)));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Hello_with_non_null_ids_is_terminated(bool withScan, bool withJob)
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Hello(scan: withScan ? ExpectedScan : null, job: withJob ? ExpectedJob : null)));
    }

    [Fact]
    public void Hello_with_skipped_sequence_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(sequence: 1)));
    }

    [Fact]
    public void Negative_sequence_is_terminated()
    {
        var validator = CreateValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(sequence: -1)));
    }

    [Fact]
    public void Identical_retransmitted_frame_is_ignored_as_duplicate()
    {
        var validator = CreateValidator();
        ProtocolEnvelope hello = Hello();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, hello));
        Assert.Equal(SessionVerdict.IgnoreDuplicate, Validate(validator, hello));
    }

    [Fact]
    public void Same_sequence_with_different_frame_bytes_is_terminated()
    {
        var validator = HandshakedValidator();
        ProtocolEnvelope replayed = Hello();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, replayed));
    }

    [Fact]
    public void Second_distinct_hello_is_terminated()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Hello(sequence: 1)));
    }

    [Fact]
    public void Hello_accepted_with_null_ids_is_accepted()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.HelloAccepted, 1)));
    }

    [Fact]
    public void Hello_accepted_with_ids_is_terminated()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.HelloAccepted, 1, ExpectedScan, ExpectedJob)));
    }

    [Fact]
    public void Parse_job_with_matching_ids_is_accepted()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept,
            Validate(validator, Message(MessageType.ParseJob, 1, ExpectedScan, ExpectedJob)));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void Parse_job_without_both_matching_ids_is_terminated(bool withScan, bool withJob)
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.ParseJob, 1, withScan ? ExpectedScan : null, withJob ? ExpectedJob : null)));
    }

    [Fact]
    public void Parse_job_with_mismatched_ids_is_terminated()
    {
        var validator = HandshakedValidator();
        var otherScan = new ScanId(Guid.Parse("44444444-4444-4444-4444-444444444444"));
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.ParseJob, 1, otherScan, ExpectedJob)));
    }

    [Theory]
    [InlineData(MessageType.ContentChunk)]
    [InlineData(MessageType.GapProduced)]
    [InlineData(MessageType.ParseCompleted)]
    [InlineData(MessageType.ParseFailed)]
    [InlineData(MessageType.CancelJob)]
    public void Job_messages_with_matching_ids_are_accepted(MessageType type)
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(type, 1, ExpectedScan, ExpectedJob)));
    }

    [Theory]
    [InlineData(MessageType.ContentChunk)]
    [InlineData(MessageType.GapProduced)]
    [InlineData(MessageType.ParseCompleted)]
    [InlineData(MessageType.ParseFailed)]
    [InlineData(MessageType.CancelJob)]
    public void Job_messages_without_ids_are_terminated(MessageType type)
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Message(type, 1)));
    }

    [Fact]
    public void Idle_heartbeat_without_ids_is_accepted()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.Heartbeat, 1)));
    }

    [Fact]
    public void Active_heartbeat_with_matching_ids_is_accepted()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept,
            Validate(validator, Message(MessageType.Heartbeat, 1, ExpectedScan, ExpectedJob)));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Heartbeat_with_only_one_id_is_terminated(bool withScan, bool withJob)
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.Heartbeat, 1, withScan ? ExpectedScan : null, withJob ? ExpectedJob : null)));
    }

    [Fact]
    public void Heartbeat_with_mismatched_ids_is_terminated()
    {
        var validator = HandshakedValidator();
        var otherJob = new JobId(Guid.Parse("55555555-5555-5555-5555-555555555555"));
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.Heartbeat, 1, ExpectedScan, otherJob)));
    }

    [Fact]
    public void Skipped_sequence_after_handshake_is_terminated()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.TerminateJob,
            Validate(validator, Message(MessageType.ContentChunk, 5, ExpectedScan, ExpectedJob)));
    }

    [Fact]
    public void Full_valid_session_flow_is_accepted()
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.HelloAccepted, 1)));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.ParseJob, 2, ExpectedScan, ExpectedJob)));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.ContentChunk, 3, ExpectedScan, ExpectedJob)));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.Heartbeat, 4)));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.GapProduced, 5, ExpectedScan, ExpectedJob)));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.ParseCompleted, 6, ExpectedScan, ExpectedJob)));
    }

    [Theory]
    [InlineData(MessageType.ParseCompleted)]
    [InlineData(MessageType.ParseFailed)]
    [InlineData(MessageType.CancelJob)]
    public void Message_after_completion_is_terminated(MessageType completingType)
    {
        var validator = HandshakedValidator();
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(completingType, 1, ExpectedScan, ExpectedJob)));
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, Message(MessageType.Heartbeat, 2)));
    }

    [Fact]
    public void Retransmitted_completion_frame_is_terminated_not_ignored()
    {
        var validator = HandshakedValidator();
        ProtocolEnvelope completion = Message(MessageType.ParseCompleted, 1, ExpectedScan, ExpectedJob);
        Assert.Equal(SessionVerdict.Accept, Validate(validator, completion));
        Assert.Equal(SessionVerdict.TerminateJob, Validate(validator, completion));
    }

    [Fact]
    public void Duplicate_of_non_terminal_frame_is_ignored_mid_session()
    {
        var validator = HandshakedValidator();
        ProtocolEnvelope chunk = Message(MessageType.ContentChunk, 1, ExpectedScan, ExpectedJob);
        Assert.Equal(SessionVerdict.Accept, Validate(validator, chunk));
        Assert.Equal(SessionVerdict.IgnoreDuplicate, Validate(validator, chunk));
        Assert.Equal(SessionVerdict.Accept, Validate(validator, Message(MessageType.ParseCompleted, 2, ExpectedScan, ExpectedJob)));
    }
}
