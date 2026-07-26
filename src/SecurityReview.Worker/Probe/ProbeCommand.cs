#if SECURITY_REVIEW_SANDBOX_PROBE
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
#endif
