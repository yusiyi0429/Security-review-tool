using System.IO.Compression;
using System.Runtime.CompilerServices;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Parses ZIP, JAR, and OpenXML archives using <see cref="ZipArchive"/>
/// in read mode. Never extracts to disk or follows encrypted entries.
/// </summary>
public sealed class ZipFormatParser : IFormatParser
{
    public string ParserId => "zip";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId is "zip" or "jar" or "openxml";
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input,
        ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        // Collect all events before yielding — C# async iterators cannot
        // yield inside a try block that has a catch clause.
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
            throw new ArgumentException("ZIP parsing requires a seekable stream.", nameof(input));

        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);

        sourceStream.Position = 0;
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(sourceStream, ZipArchiveMode.Read, leaveOpen: true);
        }
        catch (InvalidDataException ex)
        {
            events.Add(new ParserEvent.GapProduced(CorruptGap(context, $"zip_structure_invalid: {ex.Message}")));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        using (archive)
        {
            int currentDepth = 1 + CountSeparator(context.VirtualPath, "!/");
            int childDepth = currentDepth + 1;
            int entryIndex = 0;

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                string entryName = entry.FullName;

                // Guard: path validation + budget reservation
                var guard = ArchiveEntryGuard.Guard(
                    entryName, context.VirtualPath, entryIndex,
                    entry.Length, entry.CompressedLength, childDepth,
                    budget, context.ScanId, context.JobId, "zip");

                if (!guard.Succeeded)
                {
                    events.Add(guard.Gap!);
                    entryIndex++;
                    continue;
                }

                string virtualPath = guard.VirtualPath!;

                // Directories: skip
                if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
                {
                    entryIndex++;
                    continue;
                }

                // Try to open entry to detect encryption
                Stream? entryStream = null;
                bool isEncrypted = false;
                try
                {
                    entryStream = entry.Open();
                }
                catch (InvalidDataException ex) when (
                    ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    ex.Message.Contains("encrypt", StringComparison.OrdinalIgnoreCase))
                {
                    isEncrypted = true;
                }

                if (isEncrypted)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "zip",
                        "zip_parse", GapReason.Encrypted, "encrypted_entry",
                        entry.Length, entry.CompressedLength, DateTimeOffset.UtcNow)));
                    entryIndex++;
                    continue;
                }

                if (entryStream == null)
                {
                    entryIndex++;
                    continue;
                }

                // Copy entry data to memory for sniffer (ZipArchiveEntry.Open()
                // returns a non-seekable stream; FormatSniffer requires seekable).
                long maxRead = Math.Min(entry.Length, ArchiveBudget.MaxBytesPerEntry);
                if (maxRead <= 0) maxRead = ArchiveBudget.MaxBytesPerEntry;
                if (maxRead > int.MaxValue) maxRead = int.MaxValue;

                var buffer = new byte[(int)maxRead];
                int totalRead = 0;
                int read;
                while (totalRead < buffer.Length &&
                       (read = await entryStream.ReadAsync(
                           buffer.AsMemory(totalRead, buffer.Length - totalRead),
                           cancellationToken).ConfigureAwait(false)) > 0)
                {
                    totalRead += read;
                }
                entryStream.Dispose();

                if (totalRead == 0 && entry.Length > 0)
                {
                    entryIndex++;
                    continue;
                }

                if (totalRead == 0)
                {
                    entryIndex++;
                    continue;
                }

                using var memStream = new MemoryStream(buffer, 0, totalRead, writable: false);

                // Sniff the entry content
                FormatProbe probe;
                try
                {
                    probe = await FormatSniffer.ProbeAsync(memStream, null, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "zip",
                        "zip_sniff", GapReason.Corrupt, $"sniff_failed: {ex.Message}",
                        totalRead, entry.CompressedLength, DateTimeOffset.UtcNow)));
                    entryIndex++;
                    continue;
                }

                // Emit ChildDiscovered with stream factory
                byte[] capturedData = buffer[..totalRead];
                Func<CancellationToken, Task<Stream>> streamFactory = _ =>
                    Task.FromResult<Stream>(new MemoryStream(capturedData, writable: false));

                events.Add(new ParserEvent.ChildDiscovered(virtualPath, probe, streamFactory));

                entryIndex++;
            }
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "zip",
            "zip_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

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
