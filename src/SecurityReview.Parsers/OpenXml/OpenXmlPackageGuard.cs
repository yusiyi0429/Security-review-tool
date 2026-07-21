using System.IO.Compression;
using System.Xml;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.OpenXml;

/// <summary>
/// Pre-traversal guard that validates a seekable stream as a safe Open XML package
/// before any Open XML SDK traversal begins.
/// </summary>
public static class OpenXmlPackageGuard
{
    private const int MaxParts = 10_000;

    private static readonly byte[] OleCfbMagic =
        [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    public sealed record GuardResult(
        bool Passed,
        IReadOnlyList<ParserEvent> PreEvents,
        string? DocumentType,
        bool IsOleCfb,
        bool IsEncrypted,
        HashSet<string>? PartNames)
    {
        public static GuardResult OleCfb() =>
            new(false, [], null, true, false, null);

        public static GuardResult Encrypted(IReadOnlyList<ParserEvent> preEvents) =>
            new(false, preEvents, null, false, true, null);

        public static GuardResult Failed(IReadOnlyList<ParserEvent> preEvents) =>
            new(false, preEvents, null, false, false, null);

        public static GuardResult Success(
            IReadOnlyList<ParserEvent> preEvents, string documentType, HashSet<string> partNames) =>
            new(true, preEvents, documentType, false, false, partNames);
    }

    public static GuardResult Guard(
        Stream seekableStream,
        ArchiveBudget budget,
        ScanId scanId,
        JobId jobId,
        string virtualPath)
    {
        ArgumentNullException.ThrowIfNull(seekableStream);
        ArgumentNullException.ThrowIfNull(budget);

        // 1. Check OLE CFB magic
        seekableStream.Position = 0;
        Span<byte> magic = stackalloc byte[8];
        if (seekableStream.Read(magic) == 8 && magic.SequenceEqual(OleCfbMagic))
            return GuardResult.OleCfb();

        seekableStream.Position = 0;

        var preEvents = new List<ParserEvent>();
        var partNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var partNamesExact = new HashSet<string>(StringComparer.Ordinal);

        // 2. Open as ZIP
        ZipArchive zip;
        try
        {
            zip = new ZipArchive(seekableStream, ZipArchiveMode.Read, leaveOpen: true);
        }
        catch (InvalidDataException ex)
        {
            preEvents.Add(new ParserEvent.GapProduced(
                MakeGap(scanId, jobId, virtualPath, GapReason.Corrupt,
                    "zip_invalid", ex.Message)));
            return GuardResult.Failed(preEvents);
        }

        string? documentType = null;

        try
        {
            // 3. Validate [Content_Types].xml
            var ctEntry = zip.GetEntry("[Content_Types].xml");
            if (ctEntry == null)
            {
                preEvents.Add(new ParserEvent.GapProduced(
                    MakeGap(scanId, jobId, virtualPath, GapReason.Corrupt,
                        "missing_content_types", "Package missing [Content_Types].xml")));
                return GuardResult.Failed(preEvents);
            }

            // Check encryption
            bool hasEncryption = zip.GetEntry("EncryptionInfo") != null ||
                                 zip.GetEntry("EncryptedPackage") != null;
            if (hasEncryption)
            {
                preEvents.Add(new ParserEvent.GapProduced(
                    MakeGap(scanId, jobId, virtualPath, GapReason.Encrypted,
                        "encrypted_package", "Package is encrypted")));
                return GuardResult.Encrypted(preEvents);
            }

            // Parse content types
            try
            {
                using var ctStream = ctEntry.Open();
                documentType = ParseContentTypes(ctStream);
            }
            catch (XmlException ex)
            {
                preEvents.Add(new ParserEvent.GapProduced(
                    MakeGap(scanId, jobId, virtualPath, GapReason.Corrupt,
                        "invalid_content_types", ex.Message)));
                return GuardResult.Failed(preEvents);
            }

            // 4. Iterate entries
            int entryCount = 0;
            int depth = ComputeDepth(virtualPath);

            foreach (var entry in zip.Entries)
            {
                entryCount++;

                if (entryCount > MaxParts)
                {
                    preEvents.Add(new ParserEvent.GapProduced(
                        MakeGap(scanId, jobId, virtualPath, GapReason.ArchiveLimit,
                            "too_many_parts", $"Package exceeds {MaxParts} parts")));
                    return GuardResult.Failed(preEvents);
                }

                string entryName = entry.FullName.Replace('\\', '/').TrimEnd('/');
                if (entryName.Length == 0) continue;

                var guardResult = ArchiveEntryGuard.Guard(
                    entryName, virtualPath, entryCount - 1,
                    entry.Length, entry.CompressedLength,
                    depth, budget, scanId, jobId, "openxml");

                if (!guardResult.Succeeded)
                {
                    preEvents.Add(guardResult.Gap!);
                    continue;
                }

                string normalized = NormalizePartName(entryName);
                if (!partNames.Add(normalized))
                {
                    preEvents.Add(new ParserEvent.GapProduced(
                        MakeGap(scanId, jobId, guardResult.VirtualPath!,
                            GapReason.ArchiveLimit, "duplicate_part",
                            $"Duplicate part: {entryName}")));
                    continue;
                }

                if (!partNamesExact.Add(entryName))
                {
                    preEvents.Add(new ParserEvent.GapProduced(
                        MakeGap(scanId, jobId, guardResult.VirtualPath!,
                            GapReason.ArchiveLimit, "case_collision_part",
                            $"Case collision part: {entryName}")));
                }
            }

            // 5. Validate relationships
            var relsEntry = zip.GetEntry("_rels/.rels");
            if (relsEntry != null)
            {
                ValidateRelationships(relsEntry, scanId, jobId, virtualPath, preEvents);
            }
        }
        finally
        {
            zip.Dispose();
        }

        if (documentType == null)
        {
            preEvents.Add(new ParserEvent.GapProduced(
                MakeGap(scanId, jobId, virtualPath, GapReason.Corrupt,
                    "unknown_doc_type", "Could not determine document type")));
            return GuardResult.Failed(preEvents);
        }

        return GuardResult.Success(preEvents, documentType, partNames);
    }

    private static string? ParseContentTypes(Stream ctStream)
    {
        using var reader = XmlReader.Create(ctStream,
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

        string? docType = null;
        const string ctNs = "http://schemas.openxmlformats.org/package/2006/content-types";

        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element || reader.Name != "Override" || reader.NamespaceURI != ctNs)
                continue;

            string? partName = reader.GetAttribute("PartName");
            string? contentType = reader.GetAttribute("ContentType");

            if (partName == "/word/document.xml" &&
                contentType?.Contains("wordprocessingml.document", StringComparison.OrdinalIgnoreCase) == true)
                docType = "word";
            else if (partName == "/xl/workbook.xml" &&
                contentType?.Contains("spreadsheetml.sheet", StringComparison.OrdinalIgnoreCase) == true)
                docType = "excel";
            else if (partName == "/ppt/presentation.xml" &&
                contentType?.Contains("presentationml.presentation", StringComparison.OrdinalIgnoreCase) == true)
                docType = "powerpoint";
        }

        return docType;
    }

    private static void ValidateRelationships(
        ZipArchiveEntry relsEntry, ScanId scanId, JobId jobId,
        string virtualPath, List<ParserEvent> preEvents)
    {
        try
        {
            using var stream = relsEntry.Open();
            using var reader = XmlReader.Create(stream,
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null! });

            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element || reader.Name != "Relationship")
                    continue;

                string? target = reader.GetAttribute("Target");
                string? targetMode = reader.GetAttribute("TargetMode");
                string? relType = reader.GetAttribute("Type");

                if (string.IsNullOrEmpty(target)) continue;

                if (string.Equals(targetMode, "External", StringComparison.OrdinalIgnoreCase) ||
                    IsExternalTarget(target))
                {
                    var chunk = MakeMetadataChunk(
                        jobId, virtualPath, relsEntry.Name,
                        $"External relationship: {target} (type: {relType})");
                    preEvents.Add(new ParserEvent.ChunkProduced(chunk));
                }
            }
        }
        catch (XmlException)
        {
            preEvents.Add(new ParserEvent.GapProduced(
                MakeGap(scanId, jobId, virtualPath, GapReason.Corrupt,
                    "invalid_rels_xml", "Relationships XML is malformed")));
        }
    }

    private static bool IsExternalTarget(string target)
    {
        // A target is external if it's an absolute URL with a scheme,
        // a UNC path, or has an explicit external marker.
        // Package-relative paths (starting with /) are NOT external in OPC.
        return target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
               target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
               target.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase) ||
               target.StartsWith("file://", StringComparison.OrdinalIgnoreCase) ||
               target.StartsWith("//", StringComparison.Ordinal) ||
               (target.Length >= 2 && char.IsAsciiLetter(target[0]) && target[1] == ':');
    }

    private static string NormalizePartName(string entryName)
    {
        string normalized = entryName.ToLowerInvariant().TrimEnd('/');
        if (!normalized.StartsWith('/'))
            normalized = "/" + normalized;
        return normalized;
    }

    private static int ComputeDepth(string virtualPath)
    {
        int count = 1;
        int idx = 0;
        while ((idx = virtualPath.IndexOf("!/", idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += 2;
        }
        return count;
    }

    private static ContentChunk MakeMetadataChunk(
        JobId jobId, string virtualPath, string partName, string text)
    {
        return new ContentChunk(
            1, jobId, 0, virtualPath,
            "openxml", ContentKind.Metadata,
            "utf-8", text,
            0, 0, [], false);
    }

    internal static CoverageGap MakeGap(
        ScanId scanId, JobId jobId, string virtualPath,
        GapReason reason, string detailCode, string? detail = null)
    {
        return new CoverageGap(
            Guid.NewGuid(), scanId, null,
            virtualPath, "openxml",
            "openxml_guard", reason, detailCode,
            null, null, DateTimeOffset.UtcNow);
    }
}
