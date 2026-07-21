using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using SecurityReview.Application.Abstractions;

namespace SecurityReview.Infrastructure.Persistence;

/// <summary>
/// Resolves the application's filesystem layout under
/// <c>LocalApplicationData\SecurityReviewTool</c>. Provides deterministic
/// subdirectory and file paths for config, data, rules, temp, diagnostics,
/// backups, the SQLite database file, and the keyring file.
/// </summary>
public sealed class AppDataPaths : IApplicationPaths
{
    private readonly string _basePath;

    private AppDataPaths(string basePath)
    {
        _basePath = basePath;
    }

    /// <summary>
    /// Creates paths rooted at the current user's local application data
    /// folder (per-user, non-roaming).
    /// </summary>
    public static AppDataPaths CreateDefault() =>
        new(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecurityReviewTool"));

    /// <summary>
    /// Creates paths rooted at <paramref name="basePath"/> — intended for
    /// testing so no real user app data is touched.
    /// </summary>
    public static AppDataPaths CreateForTest(string basePath) => new(basePath);

    public string BasePath => _basePath;
    public string Config => Path.Combine(_basePath, "Config");
    public string Data => Path.Combine(_basePath, "Data");
    public string Rules => Path.Combine(_basePath, "Rules");
    public string Temp => Path.Combine(_basePath, "Temp");
    public string Diagnostics => Path.Combine(_basePath, "Diagnostics");
    public string Backups => Path.Combine(_basePath, "Backups");
    public string DatabaseFile => Path.Combine(Data, "securityreview.db");
    public string KeyRingFile => Path.Combine(Config, "keyring.dat");

    /// <summary>
    /// Creates all application directories with current-user-only ACLs.
    /// Any directory that already exists is left untouched.
    /// Throws if any parent or created directory is a reparse point.
    /// </summary>
    public void EnsureCreated()
    {
        string[] dirs =
        [
            _basePath, Config, Data, Rules, Temp, Diagnostics, Backups,
            Path.GetDirectoryName(DatabaseFile)!,
            Path.GetDirectoryName(KeyRingFile)!
        ];

        foreach (var dir in dirs)
        {
            EnsureDirectory(dir);
        }
    }

    private static void EnsureDirectory(string path)
    {
        // Walk up from the root to path, checking each ancestor for reparse points.
        var check = path;
        while (check is not null)
        {
            if (Directory.Exists(check))
            {
                var info = new DirectoryInfo(check);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new IOException(
                        $"Directory '{check}' is a reparse point and cannot be used as an application data directory.");
                }
                break;
            }
            check = Path.GetDirectoryName(check);
        }

        if (Directory.Exists(path))
            return;

        Directory.CreateDirectory(path);

        // Apply current-user-only ACL on Windows.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var directoryInfo = new DirectoryInfo(path);
            var security = directoryInfo.GetAccessControl();

            // Remove inherited permissions and disable inheritance.
            security.SetAccessRuleProtection(true, preserveInheritance: false);

            // Grant current user full control.
            var currentUser = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("Unable to resolve current Windows user.");
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            directoryInfo.SetAccessControl(security);
        }
    }
}
