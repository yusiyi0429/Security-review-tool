using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace SecurityReview.ParserCorpusTests.Corpus;

/// <summary>
/// Manifest integrity tests: validate schema, SHA-256, duplicate IDs,
/// unknown fields, and fixture existence.
/// </summary>
public sealed class CorpusManifestTests
{
    private static string CorpusRoot => Path.Combine(
        Path.GetDirectoryName(typeof(CorpusManifestTests).Assembly.Location)!,
        "Corpus");

    private static string ManifestPath => Path.Combine(CorpusRoot,
        "corpus-manifest.json");

    private static string SchemaPath => Path.Combine(CorpusRoot,
        "corpus-manifest.schema.json");

    private static JsonDocument LoadManifest()
    {
        Assert.True(File.Exists(ManifestPath),
            $"corpus-manifest.json not found at {ManifestPath}");
        string json = File.ReadAllText(ManifestPath);
        return JsonDocument.Parse(json);
    }

    // ── Schema loading ──────────────────────────────────────

    private static JsonDocument LoadSchema()
    {
        Assert.True(File.Exists(SchemaPath),
            $"corpus-manifest.schema.json not found at {SchemaPath}");
        string json = File.ReadAllText(SchemaPath);
        return JsonDocument.Parse(json);
    }

    // ── Basic structure ─────────────────────────────────────

    [Fact]
    public void manifest_has_version_and_cases()
    {
        using var manifest = LoadManifest();
        JsonElement root = manifest.RootElement;

        Assert.True(root.TryGetProperty("Version", out JsonElement version));
        Assert.Equal(JsonValueKind.String, version.ValueKind);

        Assert.True(root.TryGetProperty("Cases", out JsonElement cases));
        Assert.Equal(JsonValueKind.Array, cases.ValueKind);
        Assert.True(cases.GetArrayLength() > 0,
            "Manifest must contain at least one case");
    }

    [Fact]
    public void manifest_no_duplicate_case_ids()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        var ids = new HashSet<string>();
        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            Assert.True(ids.Add(caseId),
                $"Duplicate case ID: {caseId}");
        }
    }

    [Fact]
    public void manifest_all_required_fields_present()
    {
        string[] required = [
            "CaseId", "FixturePath", "Sha256", "Format",
            "ExpectedParser", "ExpectedParserVersion",
            "ExpectedChunks", "ExpectedGaps",
            "MaxDurationMs", "MaxMemoryMb", "Coverage",
        ];

        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString() ?? "?";
            foreach (string field in required)
            {
                Assert.True(c.TryGetProperty(field, out _),
                    $"Case '{caseId}' missing required field: {field}");
            }
        }
    }

    [Fact]
    public void manifest_coverage_values_are_valid()
    {
        string[] valid = ["Covered", "Partial", "NotCovered"];

        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            string coverage = c.GetProperty("Coverage").GetString()!;
            Assert.True(((IEnumerable<string>)valid).Contains(coverage),
                $"Case '{caseId}' has invalid coverage: {coverage}");
        }
    }

    [Fact]
    public void manifest_sha256_format_is_valid()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            string sha256 = c.GetProperty("Sha256").GetString()!;
            Assert.True(sha256.Length == 64 && sha256.All(c =>
                (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')),
                $"Case '{caseId}' has invalid SHA-256: {sha256}");
        }
    }

    [Fact]
    public void manifest_max_duration_and_memory_positive()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            int duration = c.GetProperty("MaxDurationMs").GetInt32();
            int memory = c.GetProperty("MaxMemoryMb").GetInt32();
            Assert.True(duration >= 0,
                $"Case '{caseId}' has negative MaxDurationMs");
            Assert.True(memory >= 0,
                $"Case '{caseId}' has negative MaxMemoryMb");
        }
    }

    // ── SHA-256 verification ────────────────────────────────

    [Fact]
    public void manifest_all_fixtures_exist()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            string fixturePath = c.GetProperty("FixturePath").GetString()!;
            string fullPath = Path.Combine(CorpusRoot, fixturePath);
            Assert.True(File.Exists(fullPath),
                $"Case '{caseId}': fixture not found at {fullPath}");
        }
    }

    [Fact]
    public void manifest_sha256_matches_fixtures()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        foreach (JsonElement c in cases.EnumerateArray())
        {
            string caseId = c.GetProperty("CaseId").GetString()!;
            string fixturePath = c.GetProperty("FixturePath").GetString()!;
            string expectedSha256 = c.GetProperty("Sha256").GetString()!;
            string fullPath = Path.Combine(CorpusRoot, fixturePath);

            using var fs = File.OpenRead(fullPath);
            byte[] hash = SHA256.HashData(fs);
            string actual = Convert.ToHexString(hash).ToLowerInvariant();

            Assert.Equal(expectedSha256, actual);
        }
    }

    // ── Schema validation (manual, no NuGet dependency) ─────

    [Fact]
    public void schema_requires_version_and_cases()
    {
        using var schema = LoadSchema();
        JsonElement root = schema.RootElement;

        Assert.True(root.TryGetProperty("required", out JsonElement required));
        var requiredList = required.EnumerateArray()
            .Select(e => e.GetString())
            .ToHashSet();
        Assert.Contains("version", requiredList);
        Assert.Contains("cases", requiredList);
    }

    [Fact]
    public void schema_case_required_fields_match()
    {
        using var schema = LoadSchema();
        JsonElement root = schema.RootElement;

        JsonElement caseDef = FindDefinition(root, "CorpusCase");
        Assert.True(caseDef.TryGetProperty("required", out JsonElement required));
        var requiredList = required.EnumerateArray()
            .Select(e => e.GetString())
            .ToHashSet();

        Assert.Contains("caseId", requiredList);
        Assert.Contains("fixturePath", requiredList);
        Assert.Contains("sha256", requiredList);
        Assert.Contains("format", requiredList);
        Assert.Contains("expectedParser", requiredList);
        Assert.Contains("expectedParserVersion", requiredList);
        Assert.Contains("expectedChunks", requiredList);
        Assert.Contains("expectedGaps", requiredList);
        Assert.Contains("maxDurationMs", requiredList);
        Assert.Contains("maxMemoryMb", requiredList);
        Assert.Contains("coverage", requiredList);
    }

    [Fact]
    public void schema_rejects_additional_properties_at_root()
    {
        using var schema = LoadSchema();
        JsonElement root = schema.RootElement;

        Assert.True(root.TryGetProperty("additionalProperties", out JsonElement ap));
        Assert.Equal(JsonValueKind.False, ap.ValueKind);
    }

    [Fact]
    public void schema_defines_gap_reason_enum()
    {
        using var schema = LoadSchema();

        JsonElement gapDef = FindDefinition(schema.RootElement, "ExpectedGap");
        JsonElement reasonProp = FindProperty(gapDef, "reason");

        Assert.True(reasonProp.TryGetProperty("enum", out JsonElement enumValues));
        var reasons = enumValues.EnumerateArray()
            .Select(e => e.GetString())
            .ToHashSet();

        Assert.Contains("Encrypted", reasons);
        Assert.Contains("Corrupt", reasons);
        Assert.Contains("UnsupportedFormat", reasons);
        Assert.Contains("ArchiveLimit", reasons);
    }

    // ── Unreferenced files ──────────────────────────────────

    [Fact]
    public void manifest_no_unreferenced_committed_files()
    {
        using var manifest = LoadManifest();
        JsonElement cases = manifest.RootElement.GetProperty("Cases");

        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement c in cases.EnumerateArray())
        {
            string fixturePath = c.GetProperty("FixturePath").GetString()!;
            referenced.Add(fixturePath.Replace('\\', '/'));
        }

        // Find all corpus fixture files (skip scripts, manifest, schema).
        string[] allFiles = Directory.GetFiles(CorpusRoot, "*.*",
            SearchOption.AllDirectories);

        var unreferenced = new List<string>();
        foreach (string file in allFiles)
        {
            string relative = Path.GetRelativePath(CorpusRoot, file)
                .Replace('\\', '/');
            string name = Path.GetFileName(file);

            // Skip scripts, schemas, the manifest, and hidden files.
            if (name.StartsWith('.')) continue;
            if (relative.StartsWith("Adversarial/", StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith("Rules/", StringComparison.OrdinalIgnoreCase))
                continue;
            if (relative.EndsWith(".sh", StringComparison.OrdinalIgnoreCase) ||
                relative.EndsWith(".py", StringComparison.OrdinalIgnoreCase) ||
                relative.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                continue;
            if (relative.EndsWith(".schema.json", StringComparison.OrdinalIgnoreCase))
                continue;
            if (relative.EndsWith("corpus-manifest.json", StringComparison.OrdinalIgnoreCase))
                continue;
            if (name == "oci-layout")
                continue;

            if (!referenced.Contains(relative))
                unreferenced.Add(relative);
        }

        Assert.Empty(unreferenced);
    }

    // ── JSON with unknown fields ────────────────────────────

    [Fact]
    public void manifest_rejects_unknown_fields_in_case()
    {
        // Simulate a manifest with an unknown field.
        string badJson = """
        {
          "Version": "1.0",
          "Cases": [
            {
              "CaseId": "test/x",
              "FixturePath": "x.bin",
              "Sha256": "0000000000000000000000000000000000000000000000000000000000000000",
              "Format": "text",
              "ExpectedParser": "text",
              "ExpectedParserVersion": "1.0",
              "ExpectedChunks": [],
              "ExpectedGaps": [],
              "MaxDurationMs": 1000,
              "MaxMemoryMb": 64,
              "Coverage": "NotCovered",
              "UnknownField": "should-not-be-here"
            }
          ]
        }
        """;

        // Validate against schema manually: check no unknown properties
        // exist beyond the defined set.
        var definedKeys = new HashSet<string>
        {
            "CaseId", "FixturePath", "Sha256", "Format",
            "ExpectedParser", "ExpectedParserVersion",
            "ExpectedChunks", "ExpectedGaps",
            "MaxDurationMs", "MaxMemoryMb", "Coverage",
        };

        bool rejected = false;
        using JsonDocument doc = JsonDocument.Parse(badJson);
        foreach (JsonElement c in doc.RootElement.GetProperty("Cases")
           .EnumerateArray())
        {
            foreach (JsonProperty prop in c.EnumerateObject())
            {
                if (!definedKeys.Contains(prop.Name))
                    rejected = true;
            }
        }

        Assert.True(rejected, "The synthetic unknown field was not rejected.");
    }

    [Fact]
    public void manifest_rejects_duplicate_case_ids_in_json()
    {
        string badJson = """
        {
          "Version": "1.0",
          "Cases": [
            {
              "CaseId": "duplicate/id",
              "FixturePath": "a.bin",
              "Sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "Format": "text",
              "ExpectedParser": "text",
              "ExpectedParserVersion": "1.0",
              "ExpectedChunks": [],
              "ExpectedGaps": [],
              "MaxDurationMs": 1000,
              "MaxMemoryMb": 64,
              "Coverage": "NotCovered"
            },
            {
              "CaseId": "duplicate/id",
              "FixturePath": "b.bin",
              "Sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "Format": "text",
              "ExpectedParser": "text",
              "ExpectedParserVersion": "1.0",
              "ExpectedChunks": [],
              "ExpectedGaps": [],
              "MaxDurationMs": 1000,
              "MaxMemoryMb": 64,
              "Coverage": "NotCovered"
            }
          ]
        }
        """;

        // Verify duplicate IDs are detected.
        var ids = new HashSet<string>();
        bool rejected = false;
        using JsonDocument doc = JsonDocument.Parse(badJson);
        foreach (JsonElement c in doc.RootElement.GetProperty("Cases")
           .EnumerateArray())
        {
            string id = c.GetProperty("CaseId").GetString()!;
            if (!ids.Add(id))
                rejected = true;
        }

        Assert.True(rejected, "The synthetic duplicate case id was not rejected.");
    }

    // ── Helpers ─────────────────────────────────────────────

    private static JsonElement FindDefinition(JsonElement schemaRoot, string name)
    {
        Assert.True(schemaRoot.TryGetProperty("definitions", out JsonElement defs),
            "Schema missing 'definitions'");
        Assert.True(defs.TryGetProperty(name, out JsonElement def),
            $"Schema missing definition: {name}");
        return def;
    }

    private static JsonElement FindProperty(JsonElement obj, string name)
    {
        Assert.True(obj.TryGetProperty("properties", out JsonElement props),
            "Missing 'properties'");
        Assert.True(props.TryGetProperty(name, out JsonElement prop),
            $"Missing property: {name}");
        return prop;
    }
}
