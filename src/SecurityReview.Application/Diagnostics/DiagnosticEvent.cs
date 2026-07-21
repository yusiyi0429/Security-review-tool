using SecurityReview.Domain;

namespace SecurityReview.Application.Diagnostics;

/// <summary>
/// Immutable diagnostic event emitted by every transport, persistence, and
/// review step. The shape is closed: it carries a <see cref="DiagnosticCode"/>,
/// a UTC timestamp, optional scan/correlation IDs, and a closed
/// <see cref="DiagnosticFields"/> record. No endpoint URL/host, no model
/// identifier, no header value, no body, no exception text, and no
/// credential may appear anywhere in the event.
///
/// P5 emits events; P6 supplies the persistent sink that replaces
/// <see cref="NullDiagnosticSink"/>. The P6 sink must accept the same
/// payload shape — the contract defined here is the stable boundary.
/// </summary>
public sealed record DiagnosticEvent(
    DiagnosticCode Code,
    DateTimeOffset UtcTimestamp,
    ScanId? ScanId,
    string? CorrelationId,
    DiagnosticFields Fields)
{
    /// <summary>
    /// Returns a representation safe for logging at the
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Information"/>
    /// level. The output never includes any value from
    /// <see cref="DiagnosticFields"/> that could carry user data; the
    /// closed record is enumerable but only stable, non-PII fields are
    /// serialized by the logger.
    /// </summary>
    public override string ToString()
    {
        return string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"DiagnosticEvent(Code={Code}, ScanId={ScanId?.Value.ToString() ?? "<none>"}, " +
            $"CorrelationId={CorrelationId ?? "<none>"}, Utc={UtcTimestamp:O})");
    }
}
