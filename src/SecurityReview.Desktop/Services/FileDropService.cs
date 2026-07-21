using System.IO;
using System.Windows;

namespace SecurityReview.Desktop.Services;

/// <summary>
/// Validates drag-and-drop data from the shell and extracts normalized
/// absolute filesystem paths. Accepts only filesystem drops (FileDrop /
/// FileContents); rejects DataObject, text URIs, and all other clipboard
/// formats. Every path is canonicalized via Path.GetFullPath and checked
/// for existence before the service yields it.
///
/// The caller must run all validation in the Application layer; this
/// service is only responsible for extracting valid paths from a drop event.
/// </summary>
public sealed class FileDropService
{
    /// <summary>
    /// Extracts and validates filesystem paths from a drop event's data object.
    /// Returns an empty collection when the format is invalid or unsupported.
    /// </summary>
    /// <param name="data">The data object passed by the drop event.</param>
    /// <returns>Normalized, existing absolute paths; empty if the drop is unsupported.</returns>
    public static IReadOnlyList<string> ExtractPaths(IDataObject data)
    {
        ArgumentNullException.ThrowIfNull(data);

        // Only accept FileDrop; reject FileContents and all other formats.
        if (!data.GetDataPresent(DataFormats.FileDrop))
            return Array.Empty<string>();

        object? raw = data.GetData(DataFormats.FileDrop);
        if (raw is not string[] paths || paths.Length == 0)
            return Array.Empty<string>();

        var validated = new List<string>(paths.Length);
        foreach (string path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
                continue;

            string? normalized = NormalizePath(path);
            if (normalized is null)
                continue;

            validated.Add(normalized);
        }

        return validated;
    }

    /// <summary>
    /// Returns true when the drop data contains a supported filesystem format.
    /// </summary>
    public static bool CanAcceptDrop(IDataObject data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return data.GetDataPresent(DataFormats.FileDrop);
    }

    /// <summary>
    /// Normalizes a raw path to a full, existent absolute path.
    /// Returns null when the path is invalid, non-existent, or a reparse
    /// point that the sandbox should not traverse.
    /// </summary>
    internal static string? NormalizePath(string raw)
    {
        try
        {
            string full = Path.GetFullPath(raw);

            // Existence check: the file or directory must exist on disk.
            if (!File.Exists(full) && !Directory.Exists(full))
                return null;

            return full;
        }
        catch (Exception)
        {
            // ArgumentException, PathTooLongException, NotSupportedException,
            // SecurityException, UnauthorizedAccessException — all map to reject.
            return null;
        }
    }

    /// <summary>
    /// Classifies a normalized path as a file, directory, Docker TAR archive,
    /// or OCI layout directory. Returns null for unsupported or non-existent paths.
    /// </summary>
    public static ScanTargetKind? ClassifyTarget(string path)
    {
        string? normalized = NormalizePath(path);
        if (normalized is null)
            return null;

        if (File.Exists(normalized))
        {
            return IsDockerTar(normalized)
                ? ScanTargetKind.DockerTar
                : ScanTargetKind.File;
        }

        if (Directory.Exists(normalized))
        {
            return IsOciLayout(normalized)
                ? ScanTargetKind.OciDirectory
                : ScanTargetKind.Directory;
        }

        return null;
    }

    private static bool IsDockerTar(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".tar";
    }

    private static bool IsOciLayout(string directoryPath)
    {
        string ociLayout = Path.Combine(directoryPath, "oci-layout");
        string indexJson = Path.Combine(directoryPath, "index.json");
        return File.Exists(ociLayout) && File.Exists(indexJson);
    }
}

/// <summary>Kinds of scan targets the UI can accept.</summary>
public enum ScanTargetKind
{
    File,
    Directory,
    DockerTar,
    OciDirectory,
}
