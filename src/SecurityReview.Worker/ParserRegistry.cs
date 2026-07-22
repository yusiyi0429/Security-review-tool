using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Jvm;
using SecurityReview.Parsers.Models;
using SecurityReview.Parsers.Oci;
using SecurityReview.Parsers.OpenXml;
using SecurityReview.Parsers.Pdf;
using SecurityReview.Parsers.Structured;
using SecurityReview.Parsers.Text;

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

    /// <summary>Creates the complete production parser registry.</summary>
    public static ParserRegistry CreateDefault()
    {
        var registry = new ParserRegistry();
        IFormatParser[] parsers =
        [
            new TextFormatParser(),
            new XmlFormatParser(),
            new JsonFormatParser(),
            new YamlFormatParser(),
            new CsvFormatParser(),
            new OpenXmlFormatParser(),
            new PdfFormatParser(),
            new ZipFormatParser(),
            new TarFormatParser(),
            new GZipFormatParser(),
            new JarFormatParser(),
            new ModelFormatParser(),
            new DockerArchiveParser(),
            new OciLayerParser(),
        ];

        foreach (IFormatParser parser in parsers)
            registry.Register(parser);

        return registry;
    }

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
