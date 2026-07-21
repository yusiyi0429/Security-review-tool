using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.Parsers.Pdf;

/// <summary>
/// Error codes for PdfPig adapter operations. These map library exceptions
/// to machine-readable codes without leaking raw exception text.
/// </summary>
public enum PdfAdapterErrorCode
{
    /// <summary>No error.</summary>
    None,

    /// <summary>Generic internal error in PdfPig.</summary>
    InternalLibraryError,

    /// <summary>PDF is encrypted and cannot be read without a password.</summary>
    Encrypted,

    /// <summary>PDF structure is corrupt or malformed.</summary>
    CorruptStructure,

    /// <summary>PDF version not supported by PdfPig.</summary>
    UnsupportedVersion,

    /// <summary>PDF header missing or invalid.</summary>
    InvalidHeader,

    /// <summary>Cross-reference table is corrupt or invalid.</summary>
    CorruptXref,

    /// <summary>Stream declared length exceeds reasonable limits.</summary>
    StreamTooLarge,

    /// <summary>Stream data does not match declared length.</summary>
    StreamLengthMismatch,

    /// <summary>Unexpected error during parsing.</summary>
    UnexpectedError,
}

/// <summary>
/// Parsed result for a single PDF page from the PdfPig adapter.
/// </summary>
public sealed record PdfPageResult(
    int PageNumber,
    string Text,
    int TextObjectCount,
    int ImageObjectCount,
    int CharCount,
    IReadOnlyList<string> Warnings,
    PdfAdapterErrorCode ErrorCode,
    IReadOnlyList<LocationMapEntry> LocationMap)
{
    public bool HasError => ErrorCode != PdfAdapterErrorCode.None;

    public string? ErrorDetail { get; init; }
}

/// <summary>
/// Document-level information extracted from PDF metadata.
/// </summary>
public sealed record PdfDocumentInfo(
    string? Title,
    string? Author,
    string? Subject,
    string? Keywords,
    string? Creator,
    string? Producer,
    DateTimeOffset? Created,
    DateTimeOffset? Modified)
{
    public static PdfDocumentInfo Empty { get; } = new(null, null, null, null, null, null, null, null);
}

/// <summary>
/// Extracted text from a PDF annotation.
/// </summary>
public sealed record PdfAnnotationInfo(string Subtype, string? Contents, string? Destination);

/// <summary>
/// Extracted value from a PDF form field.
/// </summary>
public sealed record PdfFormFieldInfo(string Name, string? Value, string? FieldType);

/// <summary>
/// Extracted bookmark entry from PDF outlines.
/// </summary>
public sealed record PdfBookmarkInfo(string Title, int? PageNumber);

/// <summary>
/// Metadata about a PDF embedded file (attachment), without materializing bytes.
/// </summary>
public sealed record PdfAttachmentInfo(string Name, long? DeclaredLength);
