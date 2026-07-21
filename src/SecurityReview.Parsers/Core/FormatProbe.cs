namespace SecurityReview.Parsers.Core;

/// <summary>
/// Bounded byte-window produced by <see cref="FormatSniffer"/>. Carries the
/// first 64 KiB of the source, a bounded tail for ZIP/PDF trailer markers,
/// the optional file extension hint (never authoritative), and the detected
/// format result.
/// </summary>
public sealed class FormatProbe
{
    public FormatProbe(ReadOnlyMemory<byte> head, ReadOnlyMemory<byte> tail,
        string? extensionHint, long declaredLength, DetectedFormat format)
    {
        Head = head;
        Tail = tail;
        ExtensionHint = extensionHint;
        DeclaredLength = declaredLength;
        Format = format;
    }

    public ReadOnlyMemory<byte> Head { get; }
    public ReadOnlyMemory<byte> Tail { get; }
    public string? ExtensionHint { get; }
    public long DeclaredLength { get; }
    public DetectedFormat Format { get; }

    public int HeadLength => Head.Length;
    public int TailLength => Tail.Length;
}
