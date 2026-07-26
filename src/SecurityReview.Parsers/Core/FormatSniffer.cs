namespace SecurityReview.Parsers.Core;

/// <summary>
/// Reads the source head (up to 64 KiB) and a bounded tail segment to detect
/// the file format. Extension is treated as a hint only — magic bytes,
/// structure markers, and content heuristics are authority.
/// </summary>
public static class FormatSniffer
{
    private const int MaxHeadBytes = 65_536;         // 64 KiB
    private const int MaxTailBytes = 1_024;          // 1 KiB tail for trailer markers
    private const int TextSampleBytes = 4_096;       // first 4 KiB for UTF-8 / binary detection

    private const double HighConfidence = 1.0;
    private const double MediumConfidence = 0.9;
    private const double LowConfidence = 0.7;
    private const double MinConfidence = 0.5;

    /// <summary>
    /// Probes <paramref name="stream"/> (must be seekable) and returns a
    /// <see cref="FormatProbe"/> containing the head/tail bytes and the
    /// detected format.
    /// </summary>
    public static async Task<FormatProbe> ProbeAsync(Stream stream, string? extensionHint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek) throw new ArgumentException("Stream must be seekable.", nameof(stream));

        long declaredLength = stream.Length;

        // Read head (up to 64 KiB)
        int headSize = (int)Math.Min(declaredLength, MaxHeadBytes);
        byte[] headBytes = new byte[headSize];
        stream.Position = 0;
        await stream.ReadExactlyAsync(headBytes, 0, headSize, cancellationToken).ConfigureAwait(false);

        // Read tail (up to 1 KiB, only for files large enough and where
        // trailer markers matter — ZIP, PDF)
        int tailSize = 0;
        byte[] tailBytes = [];
        if (declaredLength > MaxHeadBytes)
        {
            tailSize = (int)Math.Min(declaredLength - MaxHeadBytes, MaxTailBytes);
            if (tailSize > 0)
            {
                tailBytes = new byte[tailSize];
                stream.Position = declaredLength - tailSize;
                await stream.ReadExactlyAsync(tailBytes, 0, tailSize, cancellationToken).ConfigureAwait(false);
            }
        }

        var probe = new FormatProbe(headBytes, tailBytes, NormalizeExtension(extensionHint),
            declaredLength, new DetectedFormat("unknown", 0, [], false));

        DetectedFormat format = Detect(headBytes, tailBytes, NormalizeExtension(extensionHint), declaredLength);
        return new FormatProbe(headBytes, tailBytes, NormalizeExtension(extensionHint),
            declaredLength, format);
    }

    internal static DetectedFormat Detect(ReadOnlySpan<byte> head, ReadOnlySpan<byte> tail,
        string? extensionHint, long declaredLength)
    {
        if (head.Length == 0)
            return new DetectedFormat("empty", HighConfidence, ["size_zero"], false);

        // Check magic bytes in priority order
        var evidence = new List<string>();
        string? formatId = null;
        double confidence = 0;

        // 1. ZIP family (PK\x03\x04) — includes JAR, OpenXML, Docx, Xlsx, etc.
        if (head.Length >= 4 && head[0] == 0x50 && head[1] == 0x4B && head[2] == 0x03 && head[3] == 0x04)
        {
            evidence.Add("magic_PK");
            // Check for OpenXML [Content_Types].xml in the first 512 bytes
            if (ContainsAscii(head, "[Content_Types].xml"))
            {
                formatId = "openxml";
                evidence.Add("openxml_content_types");
                confidence = HighConfidence;
            }
            else if (ContainsAscii(head, "META-INF/MANIFEST.MF") || ContainsAscii(head, "META-INF/"))
            {
                formatId = "jar";
                evidence.Add("jar_manifest");
                confidence = HighConfidence;
            }
            else
            {
                formatId = "zip";
                confidence = MediumConfidence;
            }
        }
        // 2. PDF (%PDF header + %%EOF trailer)
        else if (head.Length >= 4 && head[0] == 0x25 && head[1] == 0x50 && head[2] == 0x44 && head[3] == 0x46)
        {
            evidence.Add("magic_PDF");
            formatId = "pdf";
            confidence = tail.Length >= 5 && ContainsAscii(tail, "%%EOF") ? HighConfidence : MediumConfidence;
            if (tail.Length >= 5 && ContainsAscii(tail, "%%EOF"))
                evidence.Add("pdf_eof_trailer");
        }
        // 3. TAR (ustar magic at offset 257 in 512-byte header)
        else if (head.Length >= 262 && IsTarHeader(head))
        {
            evidence.Add("magic_TAR");
            formatId = "tar";
            confidence = HighConfidence;
        }
        // 4. GZIP
        else if (head.Length >= 2 && head[0] == 0x1F && head[1] == 0x8B)
        {
            evidence.Add("magic_GZIP");
            formatId = "gzip";
            confidence = HighConfidence;
        }
        // 5. BZIP2
        else if (head.Length >= 3 && head[0] == 0x42 && head[1] == 0x5A && head[2] == 0x68)
        {
            evidence.Add("magic_BZ2");
            formatId = "bzip2";
            confidence = HighConfidence;
        }
        // 6. XZ
        else if (head.Length >= 6 && head[0] == 0xFD && head[1] == 0x37 && head[2] == 0x7A &&
                 head[3] == 0x58 && head[4] == 0x5A && head[5] == 0x00)
        {
            evidence.Add("magic_XZ");
            formatId = "xz";
            confidence = HighConfidence;
        }
        // 7. 7-Zip
        else if (head.Length >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC &&
                 head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)
        {
            evidence.Add("magic_7Z");
            formatId = "7z";
            confidence = HighConfidence;
        }
        // 8. RAR (v4)
        else if (head.Length >= 7 && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 &&
                 head[3] == 0x21 && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x00)
        {
            evidence.Add("magic_RAR4");
            formatId = "rar";
            confidence = HighConfidence;
        }
        // 9. RAR5
        else if (head.Length >= 8 && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 &&
                 head[3] == 0x21 && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x01 && head[7] == 0x00)
        {
            evidence.Add("magic_RAR5");
            formatId = "rar";
            confidence = HighConfidence;
        }
        // 10. ELF
        else if (head.Length >= 4 && head[0] == 0x7F && head[1] == 0x45 && head[2] == 0x4C && head[3] == 0x46)
        {
            evidence.Add("magic_ELF");
            formatId = "elf";
            confidence = HighConfidence;
        }
        // 11. PE (MZ)
        else if (head.Length >= 2 && head[0] == 0x4D && head[1] == 0x5A)
        {
            evidence.Add("magic_MZ");
            formatId = "pe";
            confidence = HighConfidence;
        }
        // 12. Java class
        else if (head.Length >= 4 && head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE)
        {
            evidence.Add("magic_JAVA_CLASS");
            formatId = "java_class";
            confidence = HighConfidence;
        }
        // 13. PNG
        else if (head.Length >= 8 && head[0] == 0x89 && head[1] == 0x50 && head[2] == 0x4E &&
                 head[3] == 0x47 && head[4] == 0x0D && head[5] == 0x0A && head[6] == 0x1A && head[7] == 0x0A)
        {
            evidence.Add("magic_PNG");
            formatId = "png";
            confidence = HighConfidence;
        }
        // 14. JPEG
        else if (head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF)
        {
            evidence.Add("magic_JPEG");
            formatId = "jpeg";
            confidence = HighConfidence;
        }
        // 15. GIF
        else if (head.Length >= 6 &&
                 ((head[0] == 0x47 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x38 && head[4] == 0x37 && head[5] == 0x61) ||
                  (head[0] == 0x47 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x38 && head[4] == 0x39 && head[5] == 0x61)))
        {
            evidence.Add("magic_GIF");
            formatId = "gif";
            confidence = HighConfidence;
        }
        // 16. BMP
        else if (head.Length >= 2 && head[0] == 0x42 && head[1] == 0x4D)
        {
            evidence.Add("magic_BMP");
            formatId = "bmp";
            confidence = HighConfidence;
        }
        // 17. TIFF
        else if (head.Length >= 4 &&
                 ((head[0] == 0x49 && head[1] == 0x49 && head[2] == 0x2A && head[3] == 0x00) ||
                  (head[0] == 0x4D && head[1] == 0x4D && head[2] == 0x00 && head[3] == 0x2A)))
        {
            evidence.Add("magic_TIFF");
            formatId = "tiff";
            confidence = HighConfidence;
        }
        // 18. WAV
        else if (head.Length >= 12 && head[0] == 0x52 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x46 &&
                 head[8] == 0x57 && head[9] == 0x41 && head[10] == 0x56 && head[11] == 0x45)
        {
            evidence.Add("magic_WAV");
            formatId = "wav";
            confidence = HighConfidence;
        }
        // 19. MP4 / ISO base media
        else if (head.Length >= 12 && head[4] == 0x66 && head[5] == 0x74 && head[6] == 0x79 && head[7] == 0x70)
        {
            evidence.Add("magic_MP4");
            formatId = "mp4";
            confidence = HighConfidence;
        }
        // 20. UTF-8 / UTF-16 BOM → text
        else if (head.Length >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF)
        {
            evidence.Add("bom_utf8");
            formatId = "text";
            confidence = HighConfidence;
        }
        else if (head.Length >= 2 && head[0] == 0xFE && head[1] == 0xFF)
        {
            evidence.Add("bom_utf16be");
            formatId = "text";
            confidence = HighConfidence;
        }
        else if (head.Length >= 2 && head[0] == 0xFF && head[1] == 0xFE)
        {
            evidence.Add("bom_utf16le");
            formatId = "text";
            confidence = HighConfidence;
        }
        // 21. Heuristic: text vs binary
        else
        {
            (formatId, confidence, evidence) = ClassifyTextOrBinary(head, declaredLength);
        }

        // Structured text has no reliable magic bytes. Once content has been
        // proven to be text, use the extension only to select the safer,
        // structure-aware parser. JSON Lines and Markdown intentionally stay
        // on the streaming text parser.
        if (formatId == "text" && extensionHint is not null)
        {
            string? structuredFormat = extensionHint switch
            {
                ".json" => "json",
                ".xml" => "xml",
                ".yaml" or ".yml" => "yaml",
                ".csv" or ".tsv" => "csv",
                _ => null,
            };
            if (structuredFormat is not null)
            {
                formatId = structuredFormat;
                evidence.Add("structured_text_extension");
            }
        }

        if (formatId == "tar" && ContainsAscii(head, "manifest.json"))
        {
            formatId = "docker-archive";
            evidence.Add("docker_manifest_entry");
        }

        // Extension mismatch check
        bool mismatch = false;
        if (formatId != null && extensionHint != null)
        {
            mismatch = IsExtensionMismatch(formatId, extensionHint);
        }

        return new DetectedFormat(formatId ?? "unknown", confidence,
            evidence.AsReadOnly(), mismatch);
    }

    private static (string FormatId, double Confidence, List<string> Evidence)
        ClassifyTextOrBinary(ReadOnlySpan<byte> head, long declaredLength)
    {
        var evidence = new List<string>();
        int sampleSize = Math.Min(head.Length, TextSampleBytes);
        ReadOnlySpan<byte> sample = head[..sampleSize];

        // Check for NUL-heavy content (binary indicator)
        int nulCount = 0;
        int highByteCount = 0;  // bytes with high bit set (0x80-0xFF)
        int printableCount = 0;
        int controlCount = 0;

        for (int i = 0; i < sample.Length; i++)
        {
            byte b = sample[i];
            if (b == 0x00) nulCount++;
            else if (b >= 0x80) highByteCount++;
            else if (b >= 0x20 && b <= 0x7E) printableCount++;
            else if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) controlCount++;
        }

        double nulRatio = sample.Length > 0 ? (double)nulCount / sample.Length : 0;
        double textRatio = sample.Length > 0 ? (double)printableCount / sample.Length : 0;

        // Try strict UTF-8 decode of the sample
        bool isValidUtf8 = IsValidUtf8Strict(sample);

        if (nulRatio > 0.10 || (highByteCount > sample.Length * 0.30 && !isValidUtf8))
        {
            evidence.Add("high_nul_or_binary");
            return ("binary", HighConfidence, evidence);
        }

        if (isValidUtf8 && textRatio > 0.50)
        {
            evidence.Add("valid_utf8_text");
            return ("text", MediumConfidence, evidence);
        }

        if (isValidUtf8)
        {
            evidence.Add("valid_utf8_low_text");
            return ("text", LowConfidence, evidence);
        }

        if (textRatio > 0.70 && nulRatio <= 0.05)
        {
            evidence.Add("high_text_ratio");
            return ("text", MinConfidence, evidence);
        }

        evidence.Add("binary_heuristic");
        return ("binary", MinConfidence, evidence);
    }

    private static bool IsValidUtf8Strict(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length)
        {
            byte b = data[i];

            if (b <= 0x7F)
            {
                i++;
                continue;
            }

            int remaining;
            uint minCodePoint;
            if (b >= 0xC2 && b <= 0xDF) { remaining = 1; minCodePoint = 0x80; }
            else if (b >= 0xE0 && b <= 0xEF) { remaining = 2; minCodePoint = b == 0xE0 ? 0xA0u : 0x800u; }
            else if (b >= 0xF0 && b <= 0xF4) { remaining = 3; minCodePoint = b == 0xF0 ? 0x10000u : 0x100000u; }
            else { return false; }

            if (i + remaining >= data.Length) return false;

            uint codePoint = (uint)(b & (0x3F >> remaining));
            for (int j = 0; j < remaining; j++)
            {
                byte cb = data[i + 1 + j];
                if ((cb & 0xC0) != 0x80) return false;
                codePoint = (codePoint << 6) | (uint)(cb & 0x3F);
            }

            if (codePoint < minCodePoint) return false;
            if (codePoint is >= 0xD800 and <= 0xDFFF) return false; // surrogates
            if (codePoint > 0x10FFFF) return false;

            i += 1 + remaining;
        }

        return true;
    }

    private static bool IsTarHeader(ReadOnlySpan<byte> head)
    {
        // TAR header: 512-byte block with ustar magic at offset 257.
        // Check for "ustar\0" or "ustar \0" at offset 257 within first 512 bytes.
        if (head.Length < 262) return false;

        ReadOnlySpan<byte> block = head[..Math.Min(head.Length, 512)];
        if (block.Length < 262) return false;

        // Check magic: "ustar" at offset 257
        return block[257] == 'u' && block[258] == 's' && block[259] == 't' &&
               block[260] == 'a' && block[261] == 'r';
    }

    private static bool ContainsAscii(ReadOnlySpan<byte> data, string needle)
    {
        if (needle.Length > data.Length) return false;
        for (int i = 0; i <= data.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (data[i + j] != (byte)needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    private static string? NormalizeExtension(string? extensionHint)
    {
        if (string.IsNullOrWhiteSpace(extensionHint)) return null;
        string ext = extensionHint.Trim();
        if (!ext.StartsWith('.')) ext = "." + ext;
        return ext.ToLowerInvariant();
    }

    private static bool IsExtensionMismatch(string detectedFormat, string extensionHint)
    {
        string? normalized = NormalizeExtension(extensionHint);
        if (normalized == null) return false;

        return detectedFormat switch
        {
            "text" => normalized is not (".txt" or ".csv" or ".log" or ".md" or ".xml" or ".json"
                or ".jsonl"
                or ".yaml" or ".yml" or ".ini" or ".cfg" or ".conf" or ".html" or ".htm"
                or ".css" or ".js" or ".ts" or ".py" or ".java" or ".cs" or ".c" or ".h"
                or ".cpp" or ".hpp" or ".rs" or ".go" or ".rb" or ".php" or ".sh"
                or ".bat" or ".ps1" or ".sql" or ".r" or ".swift" or ".kt" or ".scala"
                or ".lua" or ".pl" or ".toml" or ".env" or ".gitignore" or ".dockerfile"),
            "json" => normalized != ".json",
            "xml" => normalized != ".xml",
            "yaml" => normalized is not (".yaml" or ".yml"),
            "csv" => normalized is not (".csv" or ".tsv"),
            "zip" => normalized is not (".zip" or ".jar" or ".war" or ".ear" or ".apk"
                or ".epub" or ".odt" or ".ods" or ".odp"),
            "pdf" => normalized != ".pdf",
            "pe" => normalized is not (".exe" or ".dll" or ".sys" or ".ocx" or ".scr"),
            "elf" => normalized is not (".elf" or ".so" or ".o" or ""),
            "gzip" => normalized is not (".gz" or ".tgz"),
            "bzip2" => normalized != ".bz2",
            "xz" => normalized != ".xz",
            "rar" => normalized != ".rar",
            "7z" => normalized != ".7z",
            "png" => normalized != ".png",
            "jpeg" => normalized is not (".jpg" or ".jpeg" or ".jfif"),
            "gif" => normalized != ".gif",
            "bmp" => normalized != ".bmp",
            "tiff" => normalized is not (".tiff" or ".tif"),
            "wav" => normalized != ".wav",
            "mp4" => normalized is not (".mp4" or ".m4v" or ".mov"),
            "java_class" => normalized != ".class",
            "openxml" => normalized is not (".docx" or ".xlsx" or ".pptx"),
            "jar" => normalized != ".jar",
            "tar" => normalized != ".tar",
            "docker-archive" => normalized is not (".tar" or ".docker" or ".oci"),
            _ => false,
        };
    }
}
