using System.IO.Compression;
using System.Runtime.CompilerServices;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.ParserContracts.Protocol;

namespace SecurityReview.Parsers.Jvm;

/// <summary>
/// Parses JAR archives. Reuses ZIP machinery for archive safety, then
/// routes each entry to the appropriate child parser:
/// <list type="bullet">
///   <item><c>META-INF/MANIFEST.MF</c> → text parser</item>
///   <item><c>*.class</c> → <see cref="JvmClassParser"/></item>
///   <item>other entries (resources, nested archives) → generic sniff/child</item>
/// </list>
/// All children share the parent archive's budget via <see cref="ArchiveBudget"/>.
/// </summary>
public sealed class JarFormatParser : IFormatParser
{
    public string ParserId => "jar";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId is "jar" or "zip";
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
            throw new ArgumentException("JAR parsing requires a seekable stream.", nameof(input));

        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);

        sourceStream.Position = 0;
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(sourceStream, ZipArchiveMode.Read, leaveOpen: true);
        }
        catch (InvalidDataException ex)
        {
            events.Add(new ParserEvent.GapProduced(
                CorruptGap(context, $"jar_structure_invalid: {ex.Message}")));
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

                var guard = ArchiveEntryGuard.Guard(
                    entryName, context.VirtualPath, entryIndex,
                    entry.Length, entry.CompressedLength, childDepth,
                    budget, context.ScanId, context.JobId, "jar");

                if (!guard.Succeeded)
                {
                    events.Add(guard.Gap!);
                    entryIndex++;
                    continue;
                }

                string virtualPath = guard.VirtualPath!;

                if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
                {
                    entryIndex++;
                    continue;
                }

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
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "jar",
                        "jar_parse", GapReason.Encrypted, "encrypted_entry",
                        entry.Length, entry.CompressedLength, DateTimeOffset.UtcNow)));
                    entryIndex++;
                    continue;
                }

                if (entryStream == null)
                {
                    entryIndex++;
                    continue;
                }

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

                if (totalRead == 0)
                {
                    entryIndex++;
                    continue;
                }

                using var memStream = new MemoryStream(buffer, 0, totalRead, writable: false);

                // Class files: parse the constant pool directly
                if (entryName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    EmitClassEvents(memStream, totalRead, virtualPath, context, events);
                    entryIndex++;
                    continue;
                }

                // Manifest entries are parsed as text content
                bool isManifest = entryName.Replace('\\', '/').EndsWith(
                    "META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase);
                if (isManifest)
                {
                    EmitManifestEvents(buffer, totalRead, virtualPath, context, events,
                        cancellationToken);
                    entryIndex++;
                    continue;
                }

                // Other entries: sniff and emit as generic child
                FormatProbe probe;
                try
                {
                    probe = await FormatSniffer.ProbeAsync(memStream, null, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null, virtualPath, "jar",
                        "jar_sniff", GapReason.Corrupt, $"sniff_failed: {ex.Message}",
                        totalRead, entry.CompressedLength, DateTimeOffset.UtcNow)));
                    entryIndex++;
                    continue;
                }

                byte[] captured = buffer[..totalRead];
                Func<CancellationToken, Task<Stream>> streamFactory = _ =>
                    Task.FromResult<Stream>(new MemoryStream(captured, writable: false));

                events.Add(new ParserEvent.ChildDiscovered(virtualPath, probe, streamFactory));

                entryIndex++;
            }
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static void EmitClassEvents(
        MemoryStream memStream,
        int totalRead,
        string virtualPath,
        ParseContext context,
        List<ParserEvent> events)
    {
        memStream.Position = 0;
        Span<byte> span = stackalloc byte[0];
        byte[] buffer;
        if (totalRead <= 4096)
        {
            buffer = new byte[totalRead];
        }
        else
        {
            buffer = new byte[totalRead];
        }

        if (memStream is MemoryStream ms)
        {
            ms.Position = 0;
            ms.ReadExactly(buffer, 0, totalRead);
        }

        var result = JvmClassParser.Parse(buffer);
        if (!result.IsValid)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, virtualPath, "jar",
                "jvm_class_parse",
                GapReason.Corrupt,
                $"{result.FailureReason}:{result.FailureDetail}",
                totalRead, null, DateTimeOffset.UtcNow)));
            return;
        }

        // Emit constant-pool strings as a chunk so detection rules can scan them
        var sb = new System.Text.StringBuilder();
        foreach (var entry in result.ConstantPool)
        {
            if (entry.Tag == JvmConstantTag.Utf8 && entry.Value is { Length: > 0 })
            {
                sb.Append(entry.Value).Append('\n');
            }
        }

        if (sb.Length > 0)
        {
            string text = sb.ToString();
            var chunk = new ContentChunk(
                ProtocolVersion: ProtocolConstants.Version,
                JobId: context.JobId,
                Sequence: 0,
                VirtualPath: virtualPath,
                FormatId: "jar",
                ContentKind: ContentKind.Metadata,
                Encoding: "utf-8",
                Text: text,
                SourceStart: 0,
                SourceLength: totalRead,
                LocationMap: [new LocationMapEntry(0, totalRead, 0, text.Length)],
                IsFinal: true);

            events.Add(new ParserEvent.ChunkProduced(chunk));
        }
        _ = span;
    }

    private static void EmitManifestEvents(
        byte[] buffer,
        int totalRead,
        string virtualPath,
        ParseContext context,
        List<ParserEvent> events,
        CancellationToken cancellationToken)
    {
        var detection = TextEncodingDetector.DetectAndDecode(
            new ReadOnlySpan<byte>(buffer, 0, totalRead));

        var chunker = new ContentChunker(
            context.JobId, virtualPath, "jar",
            ContentKind.Metadata,
            detection.EncodingName,
            totalRead);

        var locationMap = new List<LocationMapEntry>
        {
            new(0, totalRead, 0, detection.Text.Length)
        };

        var chunks = chunker.ChunkAll(detection.Text, locationMap, totalRead);
        foreach (var chunk in chunks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            events.Add(new ParserEvent.ChunkProduced(chunk));
        }
    }

    private static CoverageGap CorruptGap(ParseContext context, string detail) =>
        new(Guid.NewGuid(), context.ScanId, null, context.VirtualPath, "jar",
            "jar_parse", GapReason.Corrupt, detail, null, null, DateTimeOffset.UtcNow);

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
