using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecurityReview.ContractTests.Release;

/// <summary>
/// Contract tests for release-manifest.schema.json and the release manifest
/// format consumed by the packaging pipeline.
/// </summary>
public sealed class PackageManifestTests
{
    private static string SchemaPath()
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "src",
                "SecurityReview.Desktop", "Assets", "release-manifest.schema.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(
            "release-manifest.schema.json not found above the working directory.");
    }

    private static JsonNode SchemaNode()
    {
        string text = File.ReadAllText(SchemaPath());
        JsonNode node = JsonNode.Parse(text)!;
        Assert.NotNull(node);
        return node;
    }

    private static string BuildManifest(
        int schemaVersion = 1,
        string product = "SecurityReviewTool",
        string version = "1.0.0",
        string runtimeVersion = "10.0.3",
        string sdkVersion = "10.0.302",
        string targetRid = "win-x64",
        string createdUtc = "2026-01-01T00:00:00Z",
        string signerMode = "unsigned_pilot",
        string fileJson = """
            [
              {"path": "SecurityReviewTool.exe", "size": 1024, "sha256": "a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
              {"path": "worker/SecurityReview.Worker.exe", "size": 512, "sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"}
            ]
            """)
    {
        return $$"""
        {
          "schema_version": {{schemaVersion}},
          "product": "{{product}}",
          "version": "{{version}}",
          "runtime_version": "{{runtimeVersion}}",
          "sdk_version": "{{sdkVersion}}",
          "target_rid": "{{targetRid}}",
          "created_utc": "{{createdUtc}}",
          "signer_mode": "{{signerMode}}",
          "files": {{fileJson}}
        }
        """;
    }

    [Fact]
    public void Schema_file_exists_and_is_valid_json()
    {
        string path = SchemaPath();
        Assert.True(File.Exists(path), $"Schema not found at {path}");

        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement root = schema.RootElement;

        // Must be a JSON Schema with $schema keyword
        Assert.True(root.TryGetProperty("$schema", out _),
            "Schema must have a $schema property.");
        Assert.True(root.TryGetProperty("type", out JsonElement typeProp));
        Assert.Equal("object", typeProp.GetString());
    }

    [Fact]
    public void Schema_enforces_additionalProperties_false()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        Assert.False(schema.RootElement.GetProperty("additionalProperties").GetBoolean(),
            "Schema must set additionalProperties: false at the root.");
    }

    [Fact]
    public void Schema_version_is_exactly_one()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement versionProp = schema.RootElement
            .GetProperty("properties")
            .GetProperty("schema_version");
        Assert.Equal(1, versionProp.GetProperty("const").GetInt32());
    }

    [Fact]
    public void All_required_fields_are_present()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement required = schema.RootElement.GetProperty("required");
        string[] fields = required.EnumerateArray().Select(e => e.GetString()!).ToArray();

        Assert.Contains("schema_version", fields);
        Assert.Contains("product", fields);
        Assert.Contains("version", fields);
        Assert.Contains("runtime_version", fields);
        Assert.Contains("sdk_version", fields);
        Assert.Contains("target_rid", fields);
        Assert.Contains("created_utc", fields);
        Assert.Contains("signer_mode", fields);
        Assert.Contains("files", fields);
    }

    [Fact]
    public void Signer_mode_enum_contains_expected_values()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement signerEnum = schema.RootElement
            .GetProperty("properties")
            .GetProperty("signer_mode")
            .GetProperty("enum");
        string[] values = signerEnum.EnumerateArray().Select(e => e.GetString()!).ToArray();

        Assert.Contains("authenticode", values);
        Assert.Contains("unsigned_pilot", values);
    }

    [Fact]
    public void File_entry_requires_path_size_and_sha256()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement fileRequired = schema.RootElement
            .GetProperty("properties")
            .GetProperty("files")
            .GetProperty("items")
            .GetProperty("required");
        string[] fields = fileRequired.EnumerateArray().Select(e => e.GetString()!).ToArray();

        Assert.Contains("path", fields);
        Assert.Contains("size", fields);
        Assert.Contains("sha256", fields);
    }

    [Fact]
    public void Sha256_pattern_is_64_lowercase_hex()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        string pattern = schema.RootElement
            .GetProperty("properties")
            .GetProperty("files")
            .GetProperty("items")
            .GetProperty("properties")
            .GetProperty("sha256")
            .GetProperty("pattern")
            .GetString()!;

        // Match 64 lowercase hex chars exactly
        Assert.Matches(pattern, "a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
        Assert.DoesNotMatch(pattern, "A3B2C1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2");
        Assert.DoesNotMatch(pattern, "short");
        Assert.DoesNotMatch(pattern, new string('g', 64));
    }

    [Fact]
    public void File_path_disallows_backslashes_and_traversal()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        string pattern = schema.RootElement
            .GetProperty("properties")
            .GetProperty("files")
            .GetProperty("items")
            .GetProperty("properties")
            .GetProperty("path")
            .GetProperty("pattern")
            .GetString()!;

        Assert.DoesNotMatch(pattern, @"folder\file.dll");
        Assert.DoesNotMatch(pattern, "../escape.exe");
        Assert.DoesNotMatch(pattern, @"/absolute/path.exe");
        Assert.DoesNotMatch(pattern, @"C:\windows\path.exe");
        Assert.Matches(pattern, "folder/file.dll");
        Assert.Matches(pattern, "SecurityReviewTool.exe");
    }

    [Fact]
    public void File_size_is_non_negative_integer()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement sizeSchema = schema.RootElement
            .GetProperty("properties")
            .GetProperty("files")
            .GetProperty("items")
            .GetProperty("properties")
            .GetProperty("size");

        Assert.Equal("integer", sizeSchema.GetProperty("type").GetString());
        Assert.Equal(0, sizeSchema.GetProperty("minimum").GetInt32());
    }
}
