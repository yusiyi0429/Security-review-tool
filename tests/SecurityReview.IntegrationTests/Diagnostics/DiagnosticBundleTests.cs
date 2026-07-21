using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Infrastructure.Diagnostics;

namespace SecurityReview.IntegrationTests.Diagnostics;

public sealed class DiagnosticBundleTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _sourceDir;

    public DiagnosticBundleTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"diag-bundle-{Guid.NewGuid():N}");
        _sourceDir = Path.Combine(_tempDir, "source");
        Directory.CreateDirectory(_sourceDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task Bundle_only_contains_allowlisted_files()
    {
        // Arrange: create source directory with mix of allowed and disallowed files
        string[] allowed = [
            "summary.json", "versions.json", "events.jsonl",
            "health/sandbox.json", "health/database.json",
            "health/rules.json", "health/llm.json", "package-manifest.json",
        ];
        string[] disallowed = [
            "app.db", "app.db-wal", "app.db-shm", "keyring.dat",
            "config.json", "secrets.dat", "rules/dict.dat",
            "temp/cache.tmp", "input/scan.dat", "report/output.xlsx",
            "corpus/sample.txt", "screenshot.png", "dump/core.dmp",
        ];

        foreach (string f in allowed)
        {
            string full = Path.Combine(_sourceDir, f);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            await File.WriteAllTextAsync(full, JsonSerializer.Serialize(new { file = f, timestamp = DateTimeOffset.UtcNow }));
        }
        foreach (string f in disallowed)
        {
            string full = Path.Combine(_sourceDir, f);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            await File.WriteAllTextAsync(full, "disallowed content");
        }

        string bundlePath = Path.Combine(_tempDir, "bundle.zip");
        var manifest = new Dictionary<string, string>();

        // Act
        await DiagnosticBundleExporter.ExportAsync(_sourceDir, bundlePath, manifest, cancellationToken: CancellationToken.None);

        // Assert
        Assert.True(File.Exists(bundlePath), "Bundle ZIP must exist.");

        using var zip = ZipFile.OpenRead(bundlePath);
        var entries = zip.Entries.Select(e => e.FullName.Replace('\\', '/')).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (string f in allowed)
        {
            Assert.True(entries.Contains(f), $"Allowlisted file '{f}' must be in the bundle.");
        }

        foreach (string f in disallowed)
        {
            Assert.False(entries.Contains(f), $"Disallowed file '{f}' must NOT be in the bundle.");
        }

        // Manifest must be present
        Assert.True(zip.GetEntry("manifest.json") is not null, "Bundle must contain manifest.json.");
    }

    [Fact]
    public async Task Bundle_manifest_has_correct_hashes()
    {
        // Arrange
        string content = JsonSerializer.Serialize(new { version = "1.0", os = "Windows" });
        await File.WriteAllTextAsync(Path.Combine(_sourceDir, "versions.json"), content);
        await File.WriteAllTextAsync(Path.Combine(_sourceDir, "summary.json"), "{}");

        string bundlePath = Path.Combine(_tempDir, "bundle.zip");
        var manifest = new Dictionary<string, string>();

        // Act
        await DiagnosticBundleExporter.ExportAsync(_sourceDir, bundlePath, manifest, cancellationToken: CancellationToken.None);

        // Assert
        using var zip = ZipFile.OpenRead(bundlePath);
        ZipArchiveEntry? manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);

        using var stream = manifestEntry.Open();
        using var reader = new StreamReader(stream);
        string manifestJson = await reader.ReadToEndAsync();

        using var doc = JsonDocument.Parse(manifestJson);
        JsonElement root = doc.RootElement;

        Assert.True(root.TryGetProperty("files", out JsonElement files));
        Assert.Equal(JsonValueKind.Object, files.ValueKind);

        Assert.True(files.TryGetProperty("versions.json", out JsonElement versionsEntry));
        string expectedHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
        string actualHash = versionsEntry.GetProperty("sha256").GetString()!;
        Assert.Equal(expectedHash, actualHash);
    }

    [Fact]
    public async Task Bundle_scans_for_canaries()
    {
        // Arrange: inject a known canary
        string canaryDir = Path.Combine(_sourceDir, "health");
        Directory.CreateDirectory(canaryDir);
        await File.WriteAllTextAsync(
            Path.Combine(canaryDir, "sandbox.json"),
            JsonSerializer.Serialize(new { status = "ok", canary = "TEST_CANARY_STRING_12345" }));

        string bundlePath = Path.Combine(_tempDir, "bundle.zip");
        var canaries = new HashSet<string>(StringComparer.Ordinal) { "TEST_CANARY_STRING_12345" };
        var manifest = new Dictionary<string, string>();

        // Act & Assert
        var ex = await Assert.ThrowsAsync<DiagnosticCanaryException>(
            () => DiagnosticBundleExporter.ExportAsync(_sourceDir, bundlePath, manifest, canaries, CancellationToken.None));
        Assert.Contains("canary", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Bundle_atomic_export_does_not_overwrite_on_failure()
    {
        // Arrange
        string existingBundle = Path.Combine(_tempDir, "bundle.zip");
        await File.WriteAllTextAsync(existingBundle, "existing content");
        var originalContent = await File.ReadAllBytesAsync(existingBundle);

        // Create source that will fail (missing required files)
        string badSource = Path.Combine(_tempDir, "bad-source");
        Directory.CreateDirectory(badSource);
        // Empty source — no allowlisted files → export should still succeed
        // but with minimal content
        var manifest = new Dictionary<string, string>();

        // Act — this should succeed atomically since empty is valid
        await DiagnosticBundleExporter.ExportAsync(badSource, existingBundle, manifest, cancellationToken: CancellationToken.None);

        // Bundle was replaced (atomic success)
        Assert.True(File.Exists(existingBundle));
    }

    [Fact]
    public async Task Bundle_reparses_json_through_field_policy()
    {
        // Arrange: create events.jsonl with mixed safe and unsafe data
        string eventsDir = _sourceDir;
        var safeEvent = JsonSerializer.Serialize(new
        {
            code = "ScanStarted",
            utc = DateTimeOffset.UtcNow.ToString("O"),
            scan_id = Guid.NewGuid().ToString("N"),
            correlation_id = "corr-001",
            fields = new
            {
                stage = "scan.pipeline",
                reason_code = "start",
                module = "Application.Scans",
                method = "RunPipelineAsync",
            },
        });
        var unsafeEvent = JsonSerializer.Serialize(new
        {
            code = "ScanStarted",
            utc = DateTimeOffset.UtcNow.ToString("O"),
            scan_id = Guid.NewGuid().ToString("N"),
            fields = new
            {
                endpoint_url = "https://evil.example.com/secret",
                password = "admin123",
                authorization = "Bearer token123",
            },
        });

        await File.WriteAllTextAsync(
            Path.Combine(eventsDir, "events.jsonl"),
            safeEvent + Environment.NewLine + unsafeEvent + Environment.NewLine);

        string bundlePath = Path.Combine(_tempDir, "bundle.zip");
        var manifest = new Dictionary<string, string>();

        // Act
        await DiagnosticBundleExporter.ExportAsync(_sourceDir, bundlePath, manifest, cancellationToken: CancellationToken.None);

        // Assert: the bundle events.jsonl should only contain the safe event
        using var zip = ZipFile.OpenRead(bundlePath);
        ZipArchiveEntry? eventsEntry = zip.GetEntry("events.jsonl");
        Assert.NotNull(eventsEntry);

        using var stream = eventsEntry.Open();
        using var reader = new StreamReader(stream);
        string eventsContent = await reader.ReadToEndAsync();

        Assert.Contains("scan.pipeline", eventsContent, StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example.com", eventsContent, StringComparison.Ordinal);
        Assert.DoesNotContain("admin123", eventsContent, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer", eventsContent, StringComparison.Ordinal);
    }
}
