#if SECURITY_REVIEW_SANDBOX_PROBE
using System.Text.Json.Serialization;

namespace SecurityReview.Worker.Probe;

// Probe-only scenario contract. This type is compiled exclusively into the
// SECURITY_REVIEW_SANDBOX_PROBE build; production workers contain no
// path-based probe command. Keep the shape identical to the test-side mirror
// in tests/SecurityReview.WindowsSecurityTests/Sandbox/SandboxProbeContracts.cs.
internal enum ProbeScenario
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
    ProtocolWrongBuild,
}

[JsonConverter(typeof(JsonStringEnumConverter<ProbeAccess>))]
internal enum ProbeAccess { Unknown, Allowed, Denied, Error }

internal sealed record ProbeNetworkAttempt(string Target, ProbeAccess Access, string? ErrorKind);

internal sealed record SandboxProbeResult(
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
#endif
