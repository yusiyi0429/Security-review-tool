using System.IO;

namespace SecurityReview.Desktop.Services;

/// <summary>
/// Opens the Windows File Explorer at a trusted file path or
/// the outer file of a nested content locator. "Open externally"
/// always requires a fresh warning dialog and confirmation.
/// Never auto-opens from scan/import/preview.
/// </summary>
public sealed class ExplorerService
{
    private readonly Func<string, bool> _showExternalOpenWarning;

    /// <summary>
    /// Creates an explorer service. The <paramref name="showExternalOpenWarning"/>
    /// delegate is called before any external open and must return true to proceed.
    /// </summary>
    public ExplorerService(Func<string, bool> showExternalOpenWarning)
    {
        _showExternalOpenWarning = showExternalOpenWarning ?? throw new ArgumentNullException(nameof(showExternalOpenWarning));
    }

    /// <summary>
    /// Locates the file in Windows Explorer. For nested content (e.g. ZIP entries),
    /// locates the outer container file instead. Never opens the file itself.
    /// </summary>
    public static bool LocateInExplorer(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path is required.", nameof(filePath));

        string fullPath = Path.GetFullPath(filePath);

        if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
            return false;

        // Open Explorer with /select to highlight the file
        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{fullPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            System.Diagnostics.Process.Start(startInfo);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Resolves the outer file path for a potentially nested locator.
    /// NestedLocator returns the outer file; all others return the path as-is.
    /// </summary>
    public static string ResolveOuterPath(string filePath, string? virtualPath)
    {
        // For nested content (ZIP entries, OCI layers), locate the container
        if (virtualPath is not null && virtualPath.Contains('!', StringComparison.Ordinal))
        {
            return virtualPath[..virtualPath.IndexOf('!')];
        }
        return filePath;
    }

    /// <summary>
    /// Opens a file with the associated application after showing a warning
    /// dialog explaining untrusted code/macro/link risk. Requires explicit
    /// confirmation each time. Never auto-open.
    /// </summary>
    public bool OpenExternally(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path is required.", nameof(filePath));

        string fullPath = Path.GetFullPath(filePath);

        if (!File.Exists(fullPath))
            return false;

        // Show warning dialog and require fresh confirmation
        if (!_showExternalOpenWarning(fullPath))
            return false;

        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = fullPath,
                UseShellExecute = true,
                Verb = "open",
            };
            System.Diagnostics.Process.Start(startInfo);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Opens an HTTP/HTTPS URL in the default browser after showing a
    /// warning dialog and requiring fresh confirmation. Used by the update
    /// dialog to open the release page. Never auto-opens.
    /// </summary>
    public bool OpenUrl(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);

        if (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps)
            return false;

        if (!_showExternalOpenWarning(url.AbsoluteUri))
            return false;

        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = url.AbsoluteUri,
                UseShellExecute = true,
            };
            System.Diagnostics.Process.Start(startInfo);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the warning message text for opening a URL in the browser.
    /// </summary>
    public static string GetOpenUrlWarning(Uri url)
    {
        return $"即将在默认浏览器中打开外部网页。\n\n" +
               $"地址: {url.AbsoluteUri}\n\n" +
               $"确定要继续打开吗？";
    }

    /// <summary>
    /// Returns the warning message text for external open confirmation.
    /// </summary>
    public static string GetExternalOpenWarning(string filePath)
    {
        return $"即将使用外部程序打开文件。该文件可能包含未受信任的代码、宏或链接。\n\n" +
               $"文件: {Path.GetFileName(filePath)}\n\n" +
               $"确定要继续打开吗？";
    }
}
