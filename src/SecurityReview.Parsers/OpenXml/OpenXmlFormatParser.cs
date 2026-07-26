using System.IO.Compression;
using System.Runtime.CompilerServices;
using DocumentFormat.OpenXml.Packaging;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Binary;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Parses Office Open XML documents (.docx, .xlsx, .pptx, and macro-enabled variants).
/// Never materializes full element trees or auto-resolves external content.
/// </summary>
public sealed class OpenXmlFormatParser : IFormatParser
{
    public string ParserId => "openxml";

    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "openxml";
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
            events = await CollectEventsAsync(input, context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            events =
            [
                new ParserEvent.GapProduced(MakeGap(context, GapReason.Corrupt, "openxml_error",
                    $"{ex.GetType().Name}: {ex.Message}")),
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
        ParserInput input, ParseContext context, CancellationToken ct)
    {
        var events = new List<ParserEvent>();

        if (!input.Stream.CanSeek)
        {
            events.Add(new ParserEvent.GapProduced(
                MakeGap(context, GapReason.Corrupt, "stream_not_seekable")));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        var budget = new ArchiveBudget(input.DeclaredLength);

        var guardResult = OpenXmlPackageGuard.Guard(
            input.Stream, budget, context.ScanId, context.JobId, context.VirtualPath);

        events.AddRange(guardResult.PreEvents);

        // Handle OLE CFB (legacy Office)
        if (guardResult.IsOleCfb)
        {
            events.Add(new ParserEvent.GapProduced(
                OpenXmlPackageGuard.MakeGap(context.ScanId, context.JobId, context.VirtualPath,
                    GapReason.UnsupportedFormat, "legacy_office_body_unsupported")));

            // Fall back to printable string extraction
            input.Stream.Position = 0;
            int readLen = (int)Math.Min(input.DeclaredLength, int.MaxValue);
            byte[] buffer = new byte[readLen];
            int actualRead = await input.Stream.ReadAsync(buffer.AsMemory(0, readLen), ct).ConfigureAwait(false);

            if (actualRead > 0)
            {
                var extraction = PrintableStringExtractor.Extract(buffer.AsSpan(0, actualRead));
                long seq = 0;
                foreach (var ps in extraction.Strings)
                {
                    var chunk = new ContentChunk(
                        1, context.JobId, seq++, context.VirtualPath,
                        "openxml", ContentKind.Binary, ps.Encoding, ps.Text,
                        ps.ByteOffset, ps.ByteLength, [], false);
                    events.Add(new ParserEvent.ChunkProduced(chunk));
                }
            }

            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Handle encrypted
        if (guardResult.IsEncrypted)
        {
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Handle failed guard
        if (!guardResult.Passed)
        {
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Open as Open XML Package
        input.Stream.Position = 0;
        string docType = guardResult.DocumentType!;

        // Open XML SDK stream support differs across document types and
        // runtimes after prior ZipArchive inspection. Always use a private
        // seekable copy so package parsing never retains or mutates the
        // untrusted input handle.
        int bufferSize = (int)Math.Min(input.DeclaredLength, 100_000_000);
        using var copiedStream = new MemoryStream(bufferSize);
        input.Stream.Position = 0;
        await input.Stream.CopyToAsync(copiedStream, ct).ConfigureAwait(false);
        copiedStream.Position = 0;
        Stream openStream = copiedStream;

        try
        {
            if (docType == "word")
            {
                using (var doc = WordprocessingDocument.Open(openStream, false))
                {
                    events.AddRange(PackageMetadataReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                    events.AddRange(WordContentReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                }
                ReadVbaIfPresent(openStream, context, events);
            }
            else if (docType == "excel")
            {
                using (var doc = SpreadsheetDocument.Open(openStream, false))
                {
                    events.AddRange(PackageMetadataReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                    events.AddRange(SpreadsheetContentReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                }
                ReadVbaIfPresent(openStream, context, events);
            }
            else if (docType == "powerpoint")
            {
                using (var doc = PresentationDocument.Open(openStream, false))
                {
                    events.AddRange(PackageMetadataReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                    events.AddRange(PresentationContentReader.Read(doc, context.ScanId, context.JobId, context.VirtualPath));
                }
                ReadVbaIfPresent(openStream, context, events);
            }
            else
            {
                events.Add(new ParserEvent.GapProduced(
                    MakeGap(context, GapReason.UnsupportedFormat, "unknown_doc_type", docType)));
            }
        }
        catch (Exception ex)
        {
            events.Add(new ParserEvent.GapProduced(
                MakeGap(context, GapReason.Corrupt, "openxml_parse_failed",
                    $"{ex.GetType().Name}: {ex.Message}")));

            // A malformed relationship graph can prevent the Open XML SDK from
            // opening an otherwise readable ZIP. Still scan an independently
            // discoverable VBA part as inert bytes and disclose that macro
            // semantics were not analyzed.
            ReadVbaIfPresent(openStream, context, events);
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static void ReadVbaIfPresent(
        Stream sourceStream, ParseContext context, List<ParserEvent> events)
    {
        // Try to find vbaProject.bin by re-opening the stream as ZIP.
        // The Open XML SDK doesn't expose VBA parts directly.
        try
        {
            long savedPosition = sourceStream.Position;

            // Ensure we read from beginning
            if (sourceStream.CanSeek)
                sourceStream.Position = 0;
            else
                return;  // Can't re-read non-seekable stream

            using var zip = new ZipArchive(sourceStream, ZipArchiveMode.Read, leaveOpen: true);
            var vbaEntry = zip.Entries.FirstOrDefault(entry =>
                string.Equals(
                    entry.FullName.Replace('\\', '/'),
                    "vbaProject.bin",
                    StringComparison.OrdinalIgnoreCase)
                || entry.FullName.Replace('\\', '/').EndsWith(
                    "/vbaProject.bin",
                    StringComparison.OrdinalIgnoreCase));
            if (vbaEntry == null)
            {
                sourceStream.Position = savedPosition;
                return;
            }

            // Read vbaProject.bin
            int vbaLen = (int)Math.Min(vbaEntry.Length, 100_000_000);
            byte[] vbaData = new byte[vbaLen];
            using var vbaStream = vbaEntry.Open();
            int actualRead = vbaStream.Read(vbaData, 0, vbaLen);

            // Restore position
            if (sourceStream.CanSeek)
                sourceStream.Position = savedPosition;

            if (actualRead > 0)
            {
                var scanResult = VbaVisibleStringReader.Scan(
                    vbaData.AsSpan(0, actualRead).ToArray(),
                    context.ScanId, context.JobId, context.VirtualPath, 0);

                events.AddRange(scanResult.Chunks);
                events.Add(scanResult.CoverageGap);
            }
        }
        catch
        {
            // VBA reading is optional
        }
    }

    private static CoverageGap MakeGap(
        ParseContext context, GapReason reason, string detailCode, string? detail = null)
    {
        string code = detail != null ? $"{detailCode}: {detail}" : detailCode;
        if (code.Length > 500) code = code[..500];
        return new CoverageGap(
            Guid.NewGuid(), context.ScanId, null,
            context.VirtualPath, "openxml",
            "openxml_parse", reason, code,
            null, null, DateTimeOffset.UtcNow);
    }
}
