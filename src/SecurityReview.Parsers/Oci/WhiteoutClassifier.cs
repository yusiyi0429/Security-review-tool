using System.Formats.Tar;
using SecurityReview.Parsers.Archives;

namespace SecurityReview.Parsers.Oci;

/// <summary>The type of whiteout detected in a layer TAR entry.</summary>
public enum WhiteoutKind
{
    /// <summary>Not a whiteout entry.</summary>
    None,

    /// <summary>A file that was deleted in a subsequent layer (<c>.wh.&lt;name&gt;</c>).</summary>
    Individual,

    /// <summary>A directory whose children are all deleted (<c>.wh..wh..opq</c>).</summary>
    Opaque,
}

/// <summary>Classification result for a single TAR entry.</summary>
public sealed record WhiteoutClassification(
    WhiteoutKind Kind,
    string OriginalEntryName,
    string? DeletedTarget)
{
    /// <summary>The file or directory targeted by the whiteout, or null.</summary>
    public string? DeletedTarget { get; } = DeletedTarget;
}

/// <summary>
/// Classifies OCI layer TAR entries into whiteout types.
/// Whiteout annotation never suppresses earlier chunks — it annotates
/// the entry as <c>not_in_final_view</c> but the content chunk (from an
/// earlier layer) is preserved. The caller decides how to handle the annotation.
/// </summary>
public static class WhiteoutClassifier
{
    /// <summary>Prefix for individual file whiteout entries.</summary>
    public const string WhiteoutPrefix = ".wh.";

    /// <summary>Name of the opaque directory whiteout marker.</summary>
    public const string OpaqueWhiteoutName = ".wh..wh..opq";

    /// <summary>
    /// Classifies a TAR entry by name and type.
    /// </summary>
    public static WhiteoutClassification Classify(string entryName, TarEntryType entryType)
    {
        ArgumentNullException.ThrowIfNull(entryName);

        // Strip trailing slashes for directory entries
        string name = entryName.TrimEnd('/');

        // Opaque whiteout: .wh..wh..opq
        if (name == OpaqueWhiteoutName || name.EndsWith("/" + OpaqueWhiteoutName, StringComparison.Ordinal))
        {
            string? dirPath = name == OpaqueWhiteoutName
                ? "."
                : name.Substring(0, name.Length - OpaqueWhiteoutName.Length - 1);
            return new WhiteoutClassification(WhiteoutKind.Opaque, entryName, dirPath);
        }

        // Individual whiteout: .wh.<filename>
        string baseName = Path.GetFileName(name);
        if (!string.IsNullOrEmpty(baseName) && baseName.StartsWith(WhiteoutPrefix, StringComparison.Ordinal)
            && baseName != OpaqueWhiteoutName)
        {
            string deletedFile = baseName.Substring(WhiteoutPrefix.Length);
            string? dirName = Path.GetDirectoryName(name);
            string? targetPath = string.IsNullOrEmpty(dirName)
                ? deletedFile
                : dirName.Replace('\\', '/') + "/" + deletedFile;
            return new WhiteoutClassification(WhiteoutKind.Individual, entryName, targetPath);
        }

        return new WhiteoutClassification(WhiteoutKind.None, entryName, null);
    }

    /// <summary>
    /// Returns the file/directory that would be deleted by a whiteout entry.
    /// For <c>.wh.foo</c> in directory <c>bar</c>, returns <c>bar/foo</c>.
    /// </summary>
    public static string GetWhiteoutTarget(string virtualPath)
    {
        string displayName = VirtualPath.DisplayName(virtualPath);
        var classification = Classify(displayName, TarEntryType.RegularFile);
        return classification.DeletedTarget ?? displayName;
    }
}
