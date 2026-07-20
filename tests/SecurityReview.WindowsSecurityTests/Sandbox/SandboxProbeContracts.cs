using System.Text.Json.Serialization;

namespace SecurityReview.WindowsSecurityTests.Sandbox;

// Mirror of the probe-only worker contract (src/SecurityReview.Worker/Probe).
// The JSON payload carried in MessageType.ParseCompleted is the wire contract;
// both sides keep identical shapes and enum values.
public enum ProbeScenario
{
    HandleAndSiblingRead,
    NetworkMatrix,
    TokenInspection,
    SpawnChild,
    Allocate512MiB,
    HangPastDeadline,
    CrashNonZero,
    HandleReuseAfterDispose,
    ProtocolSkipSequence,
    ProtocolConflictingDuplicate,
    ProtocolExactRetransmit,
    ProtocolOversizedFrame,
    ProtocolWrongNonce,
    ProtocolWrongBuild
}

[JsonConverter(typeof(JsonStringEnumConverter<ProbeAccess>))]
public enum ProbeAccess { Unknown, Allowed, Denied, Error }

public sealed record ProbeNetworkAttempt(string Target, ProbeAccess Access, string? ErrorKind);

public sealed record SandboxProbeResult(
    string Scenario,
    string? HandleText,
    ProbeAccess SiblingRead,
    ProbeAccess HandleWrite,
    IReadOnlyList<ProbeNetworkAttempt> NetworkAttempts,
    bool IsAppContainer,
    string? AppContainerSid,
    IReadOnlyList<string> TokenCapabilities,
    ProbeAccess ChildSpawn,
    int AllocatedMebiBytes,
    bool GroupEnumerationProven,
    string? Note)
{
    public static SandboxProbeResult Empty(string scenario) => new(
        scenario, null, ProbeAccess.Unknown, ProbeAccess.Unknown,
        [], false, null, [], ProbeAccess.Unknown, 0, false, null);
}
