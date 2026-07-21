using System.Text.RegularExpressions;

namespace SecurityReview.ContractTests.Release;

public static partial class AllowlistPatterns
{
    [GeneratedRegex(@"[\x00-\x08\x0B\x0C\x0E-\x1F]")]
    public static partial Regex ControlCharPattern();
}

/// <summary>
/// Contract tests for the package file allowlist and structural
/// expectations of the release ZIP content.
/// </summary>
public sealed class PackageContentTests
{
    private static string AllowlistPath()
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "build",
                "package-file-allowlist.txt");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(
            "package-file-allowlist.txt not found above the working directory.");
    }

    private static string[] LoadAllowlistEntries()
    {
        return File.ReadAllLines(AllowlistPath())
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToArray();
    }

    [Fact]
    public void Allowlist_file_exists_and_is_non_empty()
    {
        string path = AllowlistPath();
        Assert.True(File.Exists(path));
        string[] entries = LoadAllowlistEntries();
        Assert.NotEmpty(entries);
    }

    [Fact]
    public void Allowlist_entries_use_forward_slash_only()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            Assert.DoesNotContain("\\", entry);
        }
    }

    [Fact]
    public void Allowlist_contains_mandatory_desktop_entry()
    {
        string[] entries = LoadAllowlistEntries();
        Assert.Contains("SecurityReviewTool.exe", entries);
    }

    [Fact]
    public void Allowlist_contains_worker_directory_entries()
    {
        string[] entries = LoadAllowlistEntries();
        Assert.Contains("worker/SecurityReview.Worker.exe", entries);
    }

    [Fact]
    public void Allowlist_contains_release_metadata_entries()
    {
        string[] entries = LoadAllowlistEntries();
        Assert.Contains("release-manifest.json", entries);
        Assert.Contains("_manifest/spdx_2.2/manifest.spdx.json", entries);
    }

    [Fact]
    public void Allowlist_contains_application_asset_entries()
    {
        string[] entries = LoadAllowlistEntries();
        Assert.Contains(entries, e => e.StartsWith("Assets/", StringComparison.Ordinal));
    }

    [Fact]
    public void Allowlist_has_no_forbidden_pdb_patterns()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            Assert.False(entry.Contains(".pdb", StringComparison.OrdinalIgnoreCase),
                $"Allowlist entry '{entry}' contains .pdb pattern.");
        }
    }

    [Fact]
    public void Allowlist_has_no_forbidden_documentation_xml_patterns()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            Assert.False(entry.EndsWith(".xml", StringComparison.OrdinalIgnoreCase),
                $"Allowlist entry '{entry}' looks like a compiler XML doc file.");
        }
    }

    [Fact]
    public void Allowlist_has_no_backslash_or_traversal()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            Assert.DoesNotContain("\\", entry);
            Assert.DoesNotContain("../", entry);
            Assert.DoesNotContain("..\\", entry);
            Assert.False(Path.IsPathRooted(entry),
                $"Allowlist entry '{entry}' is an absolute path.");
        }
    }

    [Fact]
    public void Allowlist_has_no_nul_bytes_or_control_characters()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            Assert.DoesNotContain('\0', entry);
            Assert.False(AllowlistPatterns.ControlCharPattern().IsMatch(entry),
                $"Allowlist entry '{entry}' contains control characters.");
        }
    }

    [Fact]
    public void Allowlist_entries_have_no_forbidden_keywords()
    {
        string[] forbidden = new[]
        {
            "test", "corpus", "workbook", "keyring",
            "credential", "private", "dump", ".db", ".sqlite", ".sqlite3",
            "wal", "shm", ".git", "config", "temp", "report", "source"
        };

        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries)
        {
            string lower = entry.ToLowerInvariant();
            foreach (string keyword in forbidden)
            {
                Assert.False(lower.Contains(keyword, StringComparison.Ordinal),
                    $"Allowlist entry '{entry}' contains forbidden keyword '{keyword}'.");
            }
        }
    }

    [Fact]
    public void Allowlist_has_no_duplicate_entries()
    {
        string[] entries = LoadAllowlistEntries();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string entry in entries)
        {
            Assert.True(seen.Add(entry),
                $"Duplicate allowlist entry: '{entry}'");
        }
    }

    [Fact]
    public void Allowlist_worker_entries_are_under_worker_directory()
    {
        string[] entries = LoadAllowlistEntries();
        foreach (string entry in entries.Where(e => e.Contains("Worker", StringComparison.Ordinal)))
        {
            Assert.StartsWith("worker/", entry);
        }
    }
}
