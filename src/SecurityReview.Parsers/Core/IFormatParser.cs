namespace SecurityReview.Parsers.Core;

/// <summary>
/// Contract for a format-specific parser. Each parser registers the format it
/// handles via <see cref="CanParse"/> and produces a stream of
/// <see cref="ParserEvent"/> values during a parse.
/// </summary>
public interface IFormatParser
{
    /// <summary>Unique parser identifier (e.g. "text", "pdf", "openxml").</summary>
    string ParserId { get; }

    /// <summary>Parser version for reproducibility.</summary>
    Version ParserVersion { get; }

    /// <summary>
    /// Returns true when this parser can handle the probed format. Extension
    /// mismatches should not prevent a positive result.
    /// </summary>
    bool CanParse(FormatProbe probe);

    /// <summary>
    /// Parse the input and yield a stream of events. The returned
    /// <see cref="IAsyncEnumerable{T}"/> must be fully consumed; the caller
    /// disposes <paramref name="input"/> after enumeration completes.
    /// </summary>
    IAsyncEnumerable<ParserEvent> ParseAsync(ParserInput input, ParseContext context,
        CancellationToken cancellationToken);
}
