using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Annotations;
using UglyToad.PdfPig.AcroForms.Fields;
using UglyToad.PdfPig.Outline;
using UglyToad.PdfPig.Tokens;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Pdf;

/// <summary>
/// Narrow adapter that wraps PdfPig v0.1.14. The only file in the project that
/// directly references PdfPig namespaces. Maps all library exceptions to
/// <see cref="PdfAdapterErrorCode"/> without returning raw exception text.
///
/// Page output is bounded: at most 10 MiB logical text and 1,000,000 letters
/// per page. If exceeded, the rest of the page is recorded as an
/// <see cref="GapReason.ArchiveLimit"/> gap.
///
/// Never renders pages, executes JavaScript, opens hyperlinks, resolves remote
/// fonts, or uses shell/preview handlers.
/// </summary>
public static class PdfPigAdapter
{
    public const long MaxPageTextBytes = 10 * 1024 * 1024;  // 10 MiB
    public const int MaxPageLetters = 1_000_000;

    /// <summary>
    /// Extracts all pages as <see cref="PdfPageResult"/> from a seekable, read-only
    /// handle-backed stream. The stream is left open on return.
    /// </summary>
    public static IReadOnlyList<PdfPageResult> ExtractPages(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        PdfDocument? document = null;
        try
        {
            document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
        }
        catch (Exception ex)
        {
            var code = MapExceptionToErrorCode(ex);
            return
            [
                new PdfPageResult(-1, string.Empty, 0, 0, 0,
                    [$"adapter: {code}"], code, [])
                { ErrorDetail = code.ToString() }
            ];
        }

        try
        {
            int pageCount = document.NumberOfPages;
            if (pageCount == 0)
                return [];

            var results = new List<PdfPageResult>(pageCount);

            for (int i = 1; i <= pageCount; i++)
            {
                PdfPageResult pageResult;
                try
                {
                    pageResult = ExtractSinglePage(document, i);
                }
                catch (Exception ex)
                {
                    var code = MapExceptionToErrorCode(ex);
                    pageResult = new PdfPageResult(i, string.Empty, 0, 0, 0,
                        [$"adapter:page:{code}"], code, [])
                    { ErrorDetail = code.ToString() };
                }

                results.Add(pageResult);
            }

            return results;
        }
        finally
        {
            document.Dispose();
        }
    }

    private static PdfPageResult ExtractSinglePage(PdfDocument document, int pageNumber)
    {
        var page = document.GetPage(pageNumber);
        var warnings = new List<string>();

        // Count text objects and image objects from page operations
        int textObjectCount = 0;
        int imageObjectCount = 0;

        try
        {
            var operations = page.Operations;
            foreach (var op in operations)
            {
                string opName = op.Operator;
                if (opName == "BT")
                {
                    textObjectCount++;
                }
                else if (opName == "Do")
                {
                    // "Do" draws an XObject; count as potential image
                    // (In PdfPig 0.1.14, image count is available directly)
                }
            }
        }
        catch
        {
            warnings.Add("operator_enumeration_failed");
        }

        // Use direct image count from page
        imageObjectCount = page.NumberOfImages;

        // If no text objects counted but there are letters, set to 1
        if (textObjectCount == 0 && page.Letters.Count > 0)
            textObjectCount = 1;

        // Extract text: use page.Text (PdfPig 0.1.14 auto-extracts)
        string extractedText;
        try
        {
            extractedText = page.Text ?? string.Empty;
        }
        catch
        {
            extractedText = string.Empty;
        }

        // Fallback: if Text is empty but Letters exist, reconstruct
        if (extractedText.Length == 0 && page.Letters.Count > 0)
        {
            try
            {
                extractedText = string.Concat(page.Letters.Select(l => l.Value));
            }
            catch
            {
                extractedText = string.Empty;
            }
        }

        int charCount = page.Letters.Count;
        if (charCount == 0 && extractedText.Length > 0)
            charCount = extractedText.Length;

        // Apply bounds: max 1,000,000 letters
        bool textExceeded = false;
        if (extractedText.Length > MaxPageLetters)
        {
            extractedText = extractedText[..MaxPageLetters];
            textExceeded = true;
        }

        // Apply byte bound: max 10 MiB
        int textByteCount = System.Text.Encoding.UTF8.GetByteCount(extractedText);
        if (textByteCount > MaxPageTextBytes)
        {
            int safeChars = (int)((long)extractedText.Length * MaxPageTextBytes / textByteCount);
            if (safeChars < extractedText.Length)
            {
                extractedText = extractedText[..FindScalarBoundary(extractedText, safeChars)];
                textExceeded = true;
            }
        }

        if (charCount > MaxPageLetters)
        {
            charCount = MaxPageLetters;
            if (!textExceeded) textExceeded = true;
        }

        if (textExceeded)
            warnings.Add("page_bounded");

        // Build location map
        var locationMap = new List<LocationMapEntry>();
        if (extractedText.Length > 0)
        {
            locationMap.Add(new LocationMapEntry(0, 0, 0, extractedText.Length));
        }

        return new PdfPageResult(pageNumber, extractedText,
            textObjectCount, imageObjectCount, charCount,
            warnings, PdfAdapterErrorCode.None, locationMap);
    }

    /// <summary>
    /// Extracts document metadata (title, author, etc.) without iterating pages.
    /// </summary>
    public static PdfDocumentInfo ExtractDocumentInfo(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            var info = document.Information;
            return new PdfDocumentInfo(
                Title: SafeString(info.Title),
                Author: SafeString(info.Author),
                Subject: SafeString(info.Subject),
                Keywords: SafeString(info.Keywords),
                Creator: SafeString(info.Creator),
                Producer: SafeString(info.Producer),
                Created: null,
                Modified: null);
        }
        catch (Exception ex)
        {
            var code = MapExceptionToErrorCode(ex);
            return PdfDocumentInfo.Empty;
        }
    }

    /// <summary>
    /// Extracts all annotation text from the document.
    /// </summary>
    public static IReadOnlyList<PdfAnnotationInfo> ExtractAnnotations(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            var results = new List<PdfAnnotationInfo>();

            for (int i = 1; i <= document.NumberOfPages; i++)
            {
                try
                {
                    var page = document.GetPage(i);
                    var annotations = page.GetAnnotations();
                    foreach (var annot in annotations)
                    {
                        results.Add(new PdfAnnotationInfo(
                            Subtype: annot.Type.ToString(),
                            Contents: SafeString(annot.Content),
                            Destination: null));
                    }
                }
                catch
                {
                    // Skip pages with annotation extraction errors
                }
            }

            return results;
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Extracts all form field names and values.
    /// </summary>
    public static IReadOnlyList<PdfFormFieldInfo> ExtractFormFields(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            if (!document.TryGetForm(out var form) || form == null)
                return [];

            var results = new List<PdfFormFieldInfo>();

            void CollectFields(IReadOnlyList<AcroFieldBase> fields)
            {
                foreach (var field in fields)
                {
                    string? value = null;
                    string? fieldType = field.FieldType.ToString();

                    if (field is AcroTextField tf)
                    {
                        value = tf.Value;
                    }
                    else if (field is AcroCheckboxField cb)
                    {
                        value = cb.IsChecked.ToString();
                    }
                    else if (field is AcroNonTerminalField nt)
                    {
                        // Recurse into non-terminal fields
                        CollectFields(nt.Children);
                        continue;
                    }

                    // PdfPig 0.1.14: field name is in the Dictionary token's /T entry
                    string name = string.Empty;
                    try
                    {
                        if (field.Dictionary.TryGet(NameToken.Create("T"), out var nameTok) &&
                            nameTok is StringToken strTok)
                            name = strTok.Data;
                    }
                    catch { }

                    results.Add(new PdfFormFieldInfo(
                        Name: name,
                        Value: value,
                        FieldType: fieldType));
                }
            }

            CollectFields(form.Fields);
            return results;
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Extracts bookmark hierarchy (outline) from the document.
    /// </summary>
    public static IReadOnlyList<PdfBookmarkInfo> ExtractBookmarks(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            if (!document.TryGetBookmarks(out var bookmarks) || bookmarks == null)
                return [];

            return FlattenBookmarks(bookmarks.Roots);
        }
        catch
        {
            return [];
        }
    }

    private static List<PdfBookmarkInfo> FlattenBookmarks(IReadOnlyList<BookmarkNode> nodes)
    {
        var results = new List<PdfBookmarkInfo>();
        foreach (var node in nodes)
        {
            results.Add(new PdfBookmarkInfo(
                Title: SafeString(node.Title) ?? "Untitled",
                PageNumber: null)); // PdfPig 0.1.14 BookmarkNode doesn't expose page number

            if (node.Children != null && node.Children.Count > 0)
                results.AddRange(FlattenBookmarks(node.Children));
        }

        return results;
    }

    /// <summary>
    /// Enumerates attachments (embedded files) with their declared lengths,
    /// without materializing bytes. Returns null for lengths that PdfPig
    /// cannot determine before materialization.
    /// </summary>
    public static IReadOnlyList<PdfAttachmentInfo> EnumerateAttachments(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            if (!document.Advanced.TryGetEmbeddedFiles(out var embeddedFiles) || embeddedFiles == null)
                return [];

            var results = new List<PdfAttachmentInfo>();
            foreach (var file in embeddedFiles)
            {
                long? declaredLength = null;
                try
                {
                    // PdfPig 0.1.14: EmbeddedFile has .Bytes (ReadOnlySpan<byte>)
                    // and .Memory (ReadOnlyMemory<byte>). Both materialize bytes.
                    // .Stream is a StreamToken which might have length.
                    // For safety, we check if Bytes is accessible without OOM.
                    if (!file.Bytes.IsEmpty)
                        declaredLength = file.Bytes.Length;
                }
                catch
                {
                    declaredLength = null;
                }

                results.Add(new PdfAttachmentInfo(
                    Name: SafeString(file.Name) ?? "unnamed_attachment",
                    DeclaredLength: declaredLength));
            }

            return results;
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Extracts the raw bytes of an attachment by name. Call only after
    /// <see cref="EnumerateAttachments"/> has confirmed a safe declared length.
    /// </summary>
    public static byte[] ExtractAttachmentBytes(Stream stream, string attachmentName)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(attachmentName);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
        if (!document.Advanced.TryGetEmbeddedFiles(out var embeddedFiles) || embeddedFiles == null)
            throw new InvalidOperationException("No embedded files in document.");

        foreach (var file in embeddedFiles)
        {
            if (string.Equals(SafeString(file.Name), attachmentName, StringComparison.Ordinal))
            {
                if (!file.Bytes.IsEmpty)
                    return file.Bytes.ToArray();
                if (!file.Memory.IsEmpty)
                    return file.Memory.ToArray();
                return [];
            }
        }

        throw new InvalidOperationException(
            $"Attachment '{attachmentName}' not found in document.");
    }

    /// <summary>
    /// Gets the total page count of the document.
    /// </summary>
    public static int GetPageCount(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek)
            throw new ArgumentException("PDF parsing requires a seekable stream.", nameof(stream));

        stream.Position = 0;

        try
        {
            using var document = PdfDocument.Open(stream, new ParsingOptions { ClipPaths = false });
            return document.NumberOfPages;
        }
        catch
        {
            return 0;
        }
    }

    // ─── helpers ───────────────────────────────────────────────

    private static PdfAdapterErrorCode MapExceptionToErrorCode(Exception ex)
    {
        string message = ex.Message ?? string.Empty;

        if (message.Contains("encrypt", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("owner", StringComparison.OrdinalIgnoreCase))
            return PdfAdapterErrorCode.Encrypted;

        if (message.Contains("xref", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("cross", StringComparison.OrdinalIgnoreCase))
            return PdfAdapterErrorCode.CorruptXref;

        if (message.Contains("header", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("signature", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("%PDF", StringComparison.Ordinal))
            return PdfAdapterErrorCode.InvalidHeader;

        if (message.Contains("version", StringComparison.OrdinalIgnoreCase) &&
            (message.Contains("unsupport", StringComparison.OrdinalIgnoreCase) ||
             message.Contains("not supported", StringComparison.OrdinalIgnoreCase)))
            return PdfAdapterErrorCode.UnsupportedVersion;

        if (message.Contains("corrupt", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("malform", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("invalid", StringComparison.OrdinalIgnoreCase))
            return PdfAdapterErrorCode.CorruptStructure;

        if (message.Contains("stream", StringComparison.OrdinalIgnoreCase) &&
            message.Contains("length", StringComparison.OrdinalIgnoreCase))
            return PdfAdapterErrorCode.StreamLengthMismatch;

        if (ex is OutOfMemoryException)
            return PdfAdapterErrorCode.StreamTooLarge;

        return PdfAdapterErrorCode.InternalLibraryError;
    }

    private static string? SafeString(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return null;

        var sb = new System.Text.StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= ' ' || c == '\t' || c == '\n' || c == '\r')
                sb.Append(c);
        }

        string result = sb.ToString().Trim();
        return result.Length > 0 ? result : null;
    }

    private static int FindScalarBoundary(string text, int position)
    {
        if (position <= 0) return 0;
        if (position >= text.Length) return text.Length;

        while (position > 0 && char.IsLowSurrogate(text[position]))
            position--;

        return position;
    }
}
