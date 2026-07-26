namespace SecurityReview.Desktop.Services;

/// <summary>
/// Opens the native Windows target pickers used by the new-scan page.
/// Keeping the dialogs behind this seam lets the view model be exercised
/// without showing modal UI in tests.
/// </summary>
public interface IScanTargetPicker
{
    IReadOnlyList<string> PickFiles();

    IReadOnlyList<string> PickFolders();
}

/// <summary>
/// WPF implementation backed by the Windows common item dialogs.
/// </summary>
public sealed class WpfScanTargetPicker : IScanTargetPicker
{
    public IReadOnlyList<string> PickFiles()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择扫描文件或 Docker TAR",
            Filter = "支持的文件 (*.txt;*.md;*.csv;*.log;*.xml;*.json;*.jsonl;*.yaml;*.yml;*.tar)|" +
                "*.txt;*.md;*.csv;*.log;*.xml;*.json;*.jsonl;*.yaml;*.yml;*.tar|所有文件 (*.*)|*.*",
            Multiselect = true,
        };

        return dialog.ShowDialog() == true
            ? dialog.FileNames
            : Array.Empty<string>();
    }

    public IReadOnlyList<string> PickFolders()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "选择扫描目录或 OCI 布局目录",
            Multiselect = true,
        };

        return dialog.ShowDialog() == true
            ? dialog.FolderNames
            : Array.Empty<string>();
    }
}
