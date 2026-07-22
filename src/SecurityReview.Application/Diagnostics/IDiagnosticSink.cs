namespace SecurityReview.Application.Diagnostics;

/// <summary>
/// Receives diagnostic events emitted by the LLM transport stack (P5) and
/// later by scan/review/update stages. The contract is closed: the sink
/// may not request, derive, or store any field beyond what
/// <see cref="DiagnosticEvent"/> already contains. P6 supplies a
/// persistent implementation; P5 ships <see cref="NullDiagnosticSink"/>
/// as the composition default.
/// </summary>
public interface IDiagnosticSink
{
    /// <summary>
    /// Accepts a single event. Implementations must be safe to call
    /// from any thread; they may not throw — any error must be
    /// swallowed and recorded in a separate, isolated audit log.
    /// </summary>
    void Publish(DiagnosticEvent diagnosticEvent);
}
