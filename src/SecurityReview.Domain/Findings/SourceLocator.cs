using System.Text.Json.Serialization;

namespace SecurityReview.Domain.Findings;

public enum PathKind { Segment, Stream }

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(SourceLocator.PathLocator), "path")]
[JsonDerivedType(typeof(SourceLocator.TextLocator), "text")]
[JsonDerivedType(typeof(SourceLocator.CellLocator), "cell")]
[JsonDerivedType(typeof(SourceLocator.JsonLocator), "json")]
[JsonDerivedType(typeof(SourceLocator.NestedLocator), "nested")]
[JsonDerivedType(typeof(SourceLocator.BinaryLocator), "binary")]
[JsonDerivedType(typeof(SourceLocator.PdfLocator), "pdf")]
[JsonDerivedType(typeof(SourceLocator.OciLocator), "oci")]
public abstract record SourceLocator
{
    public const int MaxCanonicalDisplayLength = 4_096;

    public abstract string ToCanonicalDisplay();

    public virtual IReadOnlyList<string> Validate() =>
        ToCanonicalDisplay().Length > MaxCanonicalDisplayLength ? ["locator_display_too_long"] : [];

    public sealed record PathLocator(PathKind PathKind, string SegmentOrStreamName) : SourceLocator
    {
        public override string ToCanonicalDisplay() =>
            PathKind == PathKind.Stream ? $"stream:{SegmentOrStreamName}" : $"path:{SegmentOrStreamName}";
    }

    public sealed record TextLocator(long Line, long Column, long ByteStart, long ByteLength) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"text:{Line}:{Column}@{ByteStart}+{ByteLength}";
    }

    public sealed record CellLocator(string Sheet, string Cell) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"cell:{Sheet}!{Cell}";
    }

    public sealed record JsonLocator(string JsonPointer, long ByteStart, long ByteLength) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"json:{JsonPointer}@{ByteStart}+{ByteLength}";
    }

    public sealed record NestedLocator(string VirtualPath, SourceLocator Inner) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"{VirtualPath}!{Inner.ToCanonicalDisplay()}";
    }

    public sealed record BinaryLocator(string Section, long ByteOffset, long ByteLength) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"binary:{Section}@{ByteOffset}+{ByteLength}";
    }

    public sealed record PdfLocator(int Page, int BlockIndex) : SourceLocator
    {
        public override string ToCanonicalDisplay() => $"pdf:{Page}:{BlockIndex}";
    }

    public sealed record OciLocator(string ManifestDigest, string LayerDigest, int LayerIndex,
        string InternalPath, long EntryOffset) : SourceLocator
    {
        public override string ToCanonicalDisplay() =>
            $"oci:{ManifestDigest}:{LayerDigest}[{LayerIndex}]:{InternalPath}@{EntryOffset}";
    }
}
