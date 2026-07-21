using SecurityReview.Parsers.Core;

namespace SecurityReview.Worker;

/// <summary>
/// Registry that maps format identifiers to <see cref="IFormatParser"/> instances.
/// Used inside the worker process to select the correct parser for a job.
/// </summary>
public sealed class ParserRegistry
{
    private readonly Dictionary<string, IFormatParser> _parsers = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>All registered parsers.</summary>
    public IReadOnlyList<IFormatParser> Parsers => _parsers.Values.ToList().AsReadOnly();

    /// <summary>Register a parser by its <see cref="IFormatParser.ParserId"/>.</summary>
    public void Register(IFormatParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);

        if (!_parsers.TryAdd(parser.ParserId, parser))
        {
            throw new InvalidOperationException(
                $"A parser with id '{parser.ParserId}' is already registered.");
        }
    }

    /// <summary>
    /// Find a parser that can handle the given <paramref name="probe"/>.
    /// Returns null if no registered parser matches.
    /// </summary>
    public IFormatParser? FindParser(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return _parsers.Values.FirstOrDefault(p => p.CanParse(probe));
    }

    /// <summary>Get a parser by its format identifier.</summary>
    public IFormatParser? GetParser(string formatId)
    {
        _parsers.TryGetValue(formatId, out IFormatParser? parser);
        return parser;
    }
}
