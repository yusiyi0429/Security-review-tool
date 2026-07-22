namespace SecurityReview.Application.Diagnostics;

/// <summary>
/// Composition-root default that drops every event. P6 replaces this
/// with a persistent sink. The public contract — the shape of
/// <see cref="DiagnosticEvent"/> — is frozen in P5 so the P6
/// implementation can read the same payload without changes.
/// </summary>
public sealed class NullDiagnosticSink : IDiagnosticSink
{
    public void Publish(DiagnosticEvent diagnosticEvent)
    {
        // Intentional no-op. Events are dropped at the boundary until P6
        // supplies a persistent sink; the call is preserved so callers
        // do not need to branch on whether telemetry is enabled.
        _ = diagnosticEvent;
    }
}
