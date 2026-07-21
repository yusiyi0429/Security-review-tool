using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Parses GZip-compressed streams. Emits exactly one virtual child
/// containing the decompressed content. The child name is taken from
/// the GZip header's optional filename field, or <c>&lt;gzip-content&gt;</c>
/// when no filename is present.
/// </summary>
public sealed class GZipFormatParser : IFormatParser
{
    public string ParserId => "gzip";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "gzip";
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input,
        ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        List<ParserEvent> events;
        try
        {
            events = await CollectEventsAsync(input, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            events =
            [
                new ParserEvent.GapProduced(CorruptGap(context, $"unexpected: {ex.Message}")),
                new ParserEvent.ParseCompleted()
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input,
        ParseContext context,
        CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream sourceStream = input.Stream;
        if (!sourceStream.CanSeek)
            throw new ArgumentException("GZip parsing requires a seekable stream.", nameof(input));

        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);
        int currentDepth = 1 + CountSeparator(context.VirtualPath, "!/");
        int childDepth = currentDepth + 1;

        // Read GZip header to extract the optional filename
        sourceStream.Position = 0;
        string childName = ReadGzipFilename(sourceStream);

        // Guard the child name
        var guard = ArchiveEntryGuard.Guard(
            childName, context.VirtualPath, 0,
            input.DeclaredLength, input.DeclaredLength, childDepth,
            budget, context.ScanId, context.JobId, "gzip");

        if (!guard.Succeeded)
        {
            events.Add(guard.Gap!);
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        string virtualPath = guard.VirtualPath!;

        // Decompress up to the per-entry limit
        sourceStream.Position = 0;
        using var gzipStream = new GZipStream(sourceStream, CompressionMode.Decompress, leaveOpen: true);

        long maxRead = Math.Min(
            Math.Min(input.DeclaredLength * 10, ArchiveBudget.MaxBytesPerEntry),
            ArchiveBudget.MaxBytesPerEntry);
        if (maxRead > int.MaxValue)
            maxRead = int.MaxValue;

        using var decompressed = new MemoryStream();
        var buffer = new byte[8192];
        int totalDecompressed = 0;
        int read;
        while (totalDecompressed < maxRead &&
               (read = await gzipStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (totalDecompressed + read > maxRead)
                read = (int)(maxRead - totalDecompressed);

            await decompressed.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                .ConfigureAwait(false);
            totalDecompressed += read;
        }

        // Release extra budget
        if (totalDecompressed < input.DeclaredLength)
            budget.Release(input.DeclaredLength - totalDecompressed, 0);

        if (totalDecompressed == 0)
        {
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Sniff the decompressed content
        decompressed.Position = 0;
        FormatProbe probe;
        try
        {
            probe = await FormatSniffer.ProbeAsync(decompressed, null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "gzip",
                "gzip_sniff", GapReason.Corrupt, $"sniff_failed: {ex.Message}",
                totalDecompressed, input.DeclaredLength, DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Stream factory
        byte[] capturedData = decompressed.ToArray();
        Func<CancellationToken, Task<Stream>> streamFactory = _ =>
            Task.FromResult<Stream>(new MemoryStream(capturedData, writable: false));

        events.Add(new ParserEvent.ChildDiscovered(virtualPath, probe, streamFactory));
        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    /// <summary>
    /// Reads the GZip header and extracts the optional filename.
    /// If no filename is present, returns <c>&lt;gzip-content&gt;</c>.
    /// </summary>
    private static string ReadGzipFilename(Stream stream)
    {
        Span<byte> header = stackalloc byte[10];
        if (stream.Read(header) < 10)
            return "<gzip-content>";

        if (header[0] != 0x1F || header[1] != 0x8B)
            return "<gzip-content>";

        byte flags = header[3];
        bool hasFilename = (flags & 0x08) != 0;

        if (!hasFilename)
            return "<gzip-content>";

        var nameBytes = new List<byte>(256);
        int b;
        while ((b = stream.ReadByte()) > 0)
        {
            if (nameBytes.Count < 4096)
                nameBytes.Add((byte)b);
        }

        if (nameBytes.Count == 0)
            return "<gzip-content>";

        string name;
        try
        {
            name = Encoding.UTF8.GetString(nameBytes.ToArray());
        }
        catch
        {
            return "<gzip-content>";
        }

        if (string.IsNullOrWhiteSpace(name))
            return "<gzip-content>";

        name = name.Replace('\\', '/').Trim('/');

        return string.IsNullOrEmpty(name) ? "<gzip-content>" : name;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "gzip",
            "gzip_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

    private static int CountSeparator(string path, string separator)
    {
        int count = 0;
        int index = 0;
        while ((index = path.IndexOf(separator, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += separator.Length;
        }

        return count;
    }
}
