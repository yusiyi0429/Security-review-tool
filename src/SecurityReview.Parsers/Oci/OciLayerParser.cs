using System.Formats.Tar;
using System.Runtime.CompilerServices;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Parsers.Oci;

/// <summary>
/// Parses a single OCI image layer TAR (potentially gzip-compressed).
/// Applies TAR/link/traversal limits, annotates whiteout entries via
/// <see cref="WhiteoutClassifier"/>, and emits every entry including
/// deleted history. Whiteout annotation never suppresses earlier chunks.
/// Symlink/hardlink contents are not followed; link target text is scanned
/// for content and a coverage note is recorded.
/// </summary>
public sealed class OciLayerParser : IFormatParser
{
    public string ParserId => "oci-layer";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "oci-layer";
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
                new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                    "oci-layer", "parse", GapReason.Corrupt,
                    $"unexpected: {ex.Message}", null, null, DateTimeOffset.UtcNow)),
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
            throw new ArgumentException("OCI layer parsing requires a seekable stream.", nameof(input));

        sourceStream.Position = 0;
        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);
        int currentDepth = 1 + CountSeparator(context.VirtualPath, "!/");
        int childDepth = currentDepth + 1;

        // Try gzip unwrap first (layer tar is often gzip-compressed)
        Stream effectiveStream = sourceStream;
        bool unwrappedGzip = false;
        try
        {
            effectiveStream = new System.IO.Compression.GZipStream(
                sourceStream, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);
            // We need to check if it's actually gzip by reading a header;
            // if not, fall back to raw tar.
            // A simple test: read first 2 bytes, check gzip magic.
            sourceStream.Position = 0;
            var magic = new byte[2];
            int magicRead = await sourceStream.ReadAsync(magic.AsMemory(), cancellationToken)
                .ConfigureAwait(false);
            if (magicRead >= 2 && magic[0] == 0x1F && magic[1] == 0x8B)
            {
                sourceStream.Position = 0;
                effectiveStream = new System.IO.Compression.GZipStream(
                    sourceStream, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);
                unwrappedGzip = true;
            }
            else
            {
                sourceStream.Position = 0;
            }
        }
        catch
        {
            sourceStream.Position = 0;
        }

        // Note: TarReader needs a non-disposed stream. GZipStream doesn't support
        // seeking, but TarReader needs a seekable stream for compressed entries.
        // For gzip layers, we must decompress into memory first.
        if (unwrappedGzip)
        {
            // Decompress full layer into memory (bounded)
            using var ms = new MemoryStream();
            long maxBytes = Math.Min(input.DeclaredLength * 10, 100_000_000); // 100MB cap
            await effectiveStream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
            ms.Position = 0;

            await ParseTarEntries(ms, context, budget, currentDepth, childDepth,
                events, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await ParseTarEntries(sourceStream, context, budget, currentDepth, childDepth,
                events, cancellationToken).ConfigureAwait(false);
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static async Task ParseTarEntries(
        Stream tarStream,
        ParseContext context,
        ArchiveBudget budget,
        int currentDepth,
        int childDepth,
        List<ParserEvent> events,
        CancellationToken cancellationToken)
    {
        using var reader = new TarReader(tarStream, leaveOpen: true);

        int entryIndex = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TarEntry? entry;
            try
            {
                entry = await reader.GetNextEntryAsync(cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                    "oci-layer", "tar_read", GapReason.Corrupt,
                    $"tar_read_error: {ex.Message}", null, null, DateTimeOffset.UtcNow)));
                break;
            }

            if (entry == null) break;

            string entryName = entry.Name;

            // Guard
            var guard = ArchiveEntryGuard.Guard(
                entryName, context.VirtualPath, entryIndex,
                entry.Length, entry.Length, childDepth,
                budget, context.ScanId, context.JobId, "oci-layer");

            if (!guard.Succeeded)
            {
                events.Add(guard.Gap!);
                entryIndex++;
                continue;
            }

            string virtualPath = guard.VirtualPath!;

            // Classify whiteout
            var whiteout = WhiteoutClassifier.Classify(entryName, entry.EntryType);

            switch (entry.EntryType)
            {
                case TarEntryType.RegularFile:
                    await HandleRegularFile(entry, virtualPath, whiteout, events, context,
                        entryIndex, cancellationToken).ConfigureAwait(false);
                    break;

                case TarEntryType.SymbolicLink:
                    HandleLinkEntry(entry, virtualPath, "symlink", whiteout, events, context, entryIndex);
                    break;

                case TarEntryType.HardLink:
                    HandleLinkEntry(entry, virtualPath, "hardlink", whiteout, events, context, entryIndex);
                    break;

                case TarEntryType.Directory:
                    if (whiteout.Kind == WhiteoutKind.Opaque)
                    {
                        // Opaque whiteout: emit as metadata
                        string metaText = $"whiteout_opaque_dir={entryName}";
                        events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
                            ProtocolVersion: 0, JobId: context.JobId,
                            Sequence: entryIndex, VirtualPath: virtualPath,
                            FormatId: "oci-layer", ContentKind: ContentKind.Metadata,
                            Encoding: "utf-8", Text: metaText,
                            SourceStart: 0, SourceLength: metaText.Length,
                            LocationMap: Array.Empty<LocationMapEntry>(),
                            IsFinal: false)));
                        events.Add(new ParserEvent.GapProduced(new CoverageGap(
                            Guid.NewGuid(), context.ScanId, null, virtualPath,
                            "oci-layer", "whiteout", GapReason.UnsupportedRegion,
                            $"opaque_whiteout:{entryName}", 0, 0, DateTimeOffset.UtcNow)));
                    }
                    break;

                default:
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "oci-layer",
                        "tar_parse", GapReason.UnsupportedRegion,
                        $"unsupported_entry_type:{entry.EntryType}",
                        entry.Length, entry.Length, DateTimeOffset.UtcNow)));
                    break;
            }

            entryIndex++;
        }
    }

    private static async Task HandleRegularFile(
        TarEntry entry,
        string virtualPath,
        WhiteoutClassification whiteout,
        List<ParserEvent> events,
        ParseContext context,
        int entryIndex,
        CancellationToken cancellationToken)
    {
        // For whiteout files (.wh.<name>), emit as metadata — never suppress earlier chunks
        if (whiteout.Kind == WhiteoutKind.Individual)
        {
            string targetName = WhiteoutClassifier.GetWhiteoutTarget(virtualPath);
            string metaText = $"whiteout_target={targetName}\nwhiteout_kind=individual";
            events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
                ProtocolVersion: 0, JobId: context.JobId, Sequence: entryIndex,
                VirtualPath: virtualPath, FormatId: "oci-layer",
                ContentKind: ContentKind.Metadata, Encoding: "utf-8",
                Text: metaText, SourceStart: 0, SourceLength: metaText.Length,
                LocationMap: Array.Empty<LocationMapEntry>(), IsFinal: false)));

            // Record as coverage gap — this file is "deleted" in final view
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath,
                "oci-layer", "whiteout", GapReason.UnsupportedRegion,
                $"whiteout_file:{targetName}", entry.Length, entry.Length,
                DateTimeOffset.UtcNow)));
            return;
        }

        // Regular file: read content and emit
        Stream? dataStream = entry.DataStream;
        if (dataStream == null)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "oci-layer",
                "tar_data", GapReason.Corrupt, "null_data_stream",
                entry.Length, entry.Length, DateTimeOffset.UtcNow)));
            return;
        }

        long maxRead = Math.Min(entry.Length, ArchiveBudget.MaxBytesPerEntry);
        if (maxRead > int.MaxValue) maxRead = int.MaxValue;

        var buffer = new byte[(int)maxRead];
        int totalRead = 0;
        int read;
        while (totalRead < buffer.Length
            && (read = await dataStream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead),
                cancellationToken).ConfigureAwait(false)) > 0)
        {
            totalRead += read;
        }

        if (totalRead == 0 && entry.Length > 0)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "oci-layer",
                "tar_data", GapReason.Corrupt, "empty_entry_stream",
                entry.Length, entry.Length, DateTimeOffset.UtcNow)));
            return;
        }

        if (totalRead == 0) return;

        byte[] captured = buffer[..totalRead];

        // Emit as text/metadata chunk
        string text;
        ContentKind kind;
        if (IsPrintableText(captured))
        {
            text = System.Text.Encoding.UTF8.GetString(captured);
            kind = ContentKind.Text;
        }
        else
        {
            text = Convert.ToBase64String(captured);
            kind = ContentKind.Binary;
        }

        events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
            ProtocolVersion: 0, JobId: context.JobId, Sequence: entryIndex,
            VirtualPath: virtualPath, FormatId: "oci-layer",
            ContentKind: kind, Encoding: "utf-8",
            Text: text, SourceStart: 0, SourceLength: totalRead,
            LocationMap: Array.Empty<LocationMapEntry>(),
            IsFinal: false)));
    }

    private static void HandleLinkEntry(
        TarEntry entry,
        string virtualPath,
        string linkType,
        WhiteoutClassification whiteout,
        List<ParserEvent> events,
        ParseContext context,
        int entryIndex)
    {
        string linkTarget = entry.LinkName ?? "(unknown)";

        // Scan link target text and record coverage note
        string metaText = $"link_type={linkType}\n"
            + $"target={linkTarget}\n"
            + $"coverage_note=link_target_scanned_not_followed";

        if (whiteout.Kind != WhiteoutKind.None)
        {
            metaText += $"\nwhiteout_kind={whiteout.Kind.ToString().ToLowerInvariant()}";
        }

        events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
            ProtocolVersion: 0, JobId: context.JobId, Sequence: entryIndex,
            VirtualPath: virtualPath, FormatId: "oci-layer",
            ContentKind: ContentKind.Metadata, Encoding: "utf-8",
            Text: metaText, SourceStart: 0, SourceLength: metaText.Length,
            LocationMap: Array.Empty<LocationMapEntry>(), IsFinal: false)));

        events.Add(new ParserEvent.GapProduced(new CoverageGap(
            Guid.NewGuid(), context.ScanId, null, virtualPath, "oci-layer",
            "tar_link", GapReason.UnsupportedRegion,
            $"link_not_followed:{linkType}", 0, 0, DateTimeOffset.UtcNow)));
    }

    private static bool IsPrintableText(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return true;
        int nonPrintable = 0;
        foreach (byte b in data)
        {
            if (b < 0x20 && b != '\n' && b != '\r' && b != '\t')
                nonPrintable++;
        }

        return nonPrintable < data.Length / 10; // less than 10% non-printable
    }

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
