using System.Formats.Tar;
using System.Runtime.CompilerServices;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Parses TAR archives using <see cref="TarReader"/>. Symbolic and hard
/// links are recorded as metadata-only children without stream factories.
/// </summary>
public sealed class TarFormatParser : IFormatParser
{
    public string ParserId => "tar";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "tar";
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
            throw new ArgumentException("TAR parsing requires a seekable stream.", nameof(input));

        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);
        int currentDepth = 1 + CountSeparator(context.VirtualPath, "!/");
        int childDepth = currentDepth + 1;

        sourceStream.Position = 0;
        using var reader = new TarReader(sourceStream, leaveOpen: true);

        int entryIndex = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TarEntry? entry = await reader.GetNextEntryAsync(cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            if (entry == null)
                break;

            string entryName = entry.Name;

            // Guard
            var guard = ArchiveEntryGuard.Guard(
                entryName, context.VirtualPath, entryIndex,
                entry.Length, entry.Length, childDepth,
                budget, context.ScanId, context.JobId, "tar");

            if (!guard.Succeeded)
            {
                events.Add(guard.Gap!);
                entryIndex++;
                continue;
            }

            string virtualPath = guard.VirtualPath!;

            switch (entry.EntryType)
            {
                case TarEntryType.RegularFile:
                    await HandleRegularFile(entry, virtualPath, events, context,
                        cancellationToken);
                    break;

                case TarEntryType.SymbolicLink:
                case TarEntryType.HardLink:
                    HandleLinkEntry(entry, virtualPath, events, context, entryIndex);
                    break;

                case TarEntryType.Directory:
                    // Directories: skip
                    break;

                default:
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "tar",
                        "tar_parse", GapReason.UnsupportedRegion,
                        $"unsupported_entry_type:{entry.EntryType}",
                        entry.Length, entry.Length, DateTimeOffset.UtcNow)));
                    break;
            }

            entryIndex++;
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static async Task HandleRegularFile(
        TarEntry entry,
        string virtualPath,
        List<ParserEvent> events,
        ParseContext context,
        CancellationToken cancellationToken)
    {
        Stream? dataStream = entry.DataStream;

        if (dataStream == null)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "tar",
                "tar_data", GapReason.Corrupt, "null_data_stream",
                entry.Length, entry.Length, DateTimeOffset.UtcNow)));
            return;
        }

        // Copy to memory for sniffing (bounded)
        long maxRead = Math.Min(entry.Length, ArchiveBudget.MaxBytesPerEntry);
        if (maxRead > int.MaxValue)
            maxRead = int.MaxValue;

        var buffer = new byte[(int)maxRead];
        int totalRead = 0;
        int read;
        while (totalRead < buffer.Length &&
               (read = await dataStream.ReadAsync(
                   buffer.AsMemory(totalRead, buffer.Length - totalRead),
                   cancellationToken).ConfigureAwait(false)) > 0)
        {
            totalRead += read;
        }

        if (totalRead == 0 && entry.Length > 0)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "tar",
                "tar_data", GapReason.Corrupt, "empty_entry_stream",
                entry.Length, entry.Length, DateTimeOffset.UtcNow)));
            return;
        }

        if (totalRead == 0)
            return;

        using var memStream = new MemoryStream(buffer, 0, totalRead, writable: false);
        FormatProbe probe;
        try
        {
            probe = await FormatSniffer.ProbeAsync(memStream, null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "tar",
                "tar_sniff", GapReason.Corrupt, $"sniff_failed: {ex.Message}",
                totalRead, entry.Length, DateTimeOffset.UtcNow)));
            return;
        }

        byte[] capturedData = buffer[..totalRead];
        Func<CancellationToken, Task<Stream>> streamFactory = _ =>
            Task.FromResult<Stream>(new MemoryStream(capturedData, writable: false));

        events.Add(new ParserEvent.ChildDiscovered(virtualPath, probe, streamFactory));
    }

    private static void HandleLinkEntry(
        TarEntry entry,
        string virtualPath,
        List<ParserEvent> events,
        ParseContext context,
        int entryIndex)
    {
        string linkTarget = entry.LinkName ?? "(unknown)";
        string linkType = entry.EntryType == TarEntryType.SymbolicLink
            ? "symlink" : "hardlink";

        string metadataText = $"link_type={linkType}\ntarget={linkTarget}\n";

        events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
            ProtocolVersion: 0,
            JobId: context.JobId,
            Sequence: entryIndex,
            VirtualPath: virtualPath,
            FormatId: "tar",
            ContentKind: ContentKind.Metadata,
            Encoding: "utf-8",
            Text: metadataText,
            SourceStart: 0,
            SourceLength: 0,
            LocationMap: Array.Empty<LocationMapEntry>(),
            IsFinal: false)));

        events.Add(new ParserEvent.GapProduced(new CoverageGap(
            Guid.NewGuid(), context.ScanId, null, virtualPath, "tar",
            "tar_link", GapReason.UnsupportedRegion,
            $"unsupported_{linkType}",
            0, 0, DateTimeOffset.UtcNow)));
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "tar",
            "tar_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

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
