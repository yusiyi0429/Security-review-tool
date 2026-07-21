using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain.Assets;
using SecurityReview.Infrastructure.Manifest;

namespace SecurityReview.ContractTests.Manifest;

public sealed class ManifestContractTests
{
    private const string ValidManifest = """
        {
          "schema_version": 1,
          "asset_id": "synthetic-project",
          "asset_version": "1.0.0",
          "components": [{"path": ".", "asset_type": "ASSET-009"}],
          "compliance_evidence": {
            "knowledge_base_transformed": {"status": "not_applicable", "reference": null},
            "model_finetuned": {"status": "not_applicable", "reference": null},
            "third_party_authorizations": []
          }
        }
        """;

    private static readonly JsonManifestReader Reader = new();

    private static async Task<ManifestReadResult> ReadAsync(string content)
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-manifest-");
        await File.WriteAllTextAsync(Path.Combine(root.FullName, JsonManifestReader.ManifestFileName),
            content, TestContext.Current.CancellationToken);
        return await Reader.ReadAsync(root.FullName, TestContext.Current.CancellationToken);
    }

    private static async Task<ManifestReadResult> ReadBytesAsync(byte[] bytes)
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-manifest-");
        await File.WriteAllBytesAsync(Path.Combine(root.FullName, JsonManifestReader.ManifestFileName),
            bytes, TestContext.Current.CancellationToken);
        return await Reader.ReadAsync(root.FullName, TestContext.Current.CancellationToken);
    }

    private static string SchemaPath()
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "rules", "schemas",
                "security-asset-manifest-v1.schema.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("Manifest schema file not found above the working directory.");
    }

    private static string FixturePath(string name)
    {
        for (DirectoryInfo? dir = new(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
        {
            string local = Path.Combine(dir.FullName, "Manifest", "Fixtures", name);
            if (File.Exists(local))
            {
                return local;
            }

            string fromRepoRoot = Path.Combine(dir.FullName, "tests",
                "SecurityReview.ContractTests", "Manifest", "Fixtures", name);
            if (File.Exists(fromRepoRoot))
            {
                return fromRepoRoot;
            }
        }

        throw new FileNotFoundException($"Fixture '{name}' not found above the working directory.");
    }

    [Fact]
    public async Task Valid_minimal_fixture_parses_into_valid_snapshot()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-manifest-");
        File.Copy(FixturePath("valid-minimal.json"),
            Path.Combine(root.FullName, JsonManifestReader.ManifestFileName));

        ManifestReadResult result = await Reader.ReadAsync(root.FullName,
            TestContext.Current.CancellationToken);

        Assert.True(result.Found);
        Assert.True(result.Valid);
        Assert.False(result.Invalid);
        ManifestSnapshot snapshot = result.Snapshot!;
        Assert.NotNull(snapshot);
        Assert.Empty(snapshot.Errors);
        AssetManifest manifest = snapshot.Manifest!;
        Assert.NotNull(manifest);
        Assert.Equal(1, AssetManifest.SchemaVersion);
        Assert.Equal("synthetic-project", manifest.AssetId);
        Assert.Equal("1.0.0", manifest.AssetVersion);
        AssetComponent component = Assert.Single(manifest.Components);
        Assert.Equal(".", component.RelativePath);
        Assert.Equal(AssetTypeId.Parse("ASSET-009"), component.AssetType);
        Assert.Equal(ComplianceEvidenceStatus.NotApplicable,
            manifest.Evidence.KnowledgeBaseTransformed.Status);
        Assert.Equal(ComplianceEvidenceStatus.NotApplicable,
            manifest.Evidence.ModelFinetuned.Status);
        Assert.Empty(manifest.Evidence.ThirdPartyAuthorizations);
    }

    [Fact]
    public async Task Missing_manifest_returns_not_found_not_an_exception()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-manifest-");

        ManifestReadResult result = await Reader.ReadAsync(root.FullName,
            TestContext.Current.CancellationToken);

        Assert.Equal(ManifestReadResult.NotFound, result);
        Assert.False(result.Found);
        Assert.False(result.Valid);
        Assert.Null(result.Snapshot);
    }

    [Fact]
    public async Task Unknown_top_level_fields_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"schema_version\": 1,",
                "\"unexpected_field\": true,\n  \"schema_version\": 1,", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.UnknownProperty && x.JsonPointer == "/unexpected_field");
    }

    [Fact]
    public async Task Property_names_are_exactly_snake_case()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("schema_version", "schemaVersion", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.UnknownProperty && x.JsonPointer == "/schemaVersion");
        Assert.Contains(result.Snapshot.Errors,
            x => x.Code == ManifestErrorCodes.MissingProperty && x.JsonPointer == "/schema_version");
    }

    [Fact]
    public async Task Duplicate_properties_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"schema_version\": 1,",
                "\"schema_version\": 1, \"schema_version\": 1,", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.DuplicateProperty && x.JsonPointer == "/schema_version");
    }

    [Fact]
    public async Task Duplicate_nested_properties_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("{\"status\": \"not_applicable\", \"reference\": null},",
                "{\"status\": \"not_applicable\", \"status\": \"verified\", \"reference\": null},",
                StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.DuplicateProperty
                && x.JsonPointer == "/compliance_evidence/knowledge_base_transformed/status");
    }

    [Fact]
    public async Task Non_utf8_bom_is_rejected()
    {
        byte[] utf16 = System.Text.Encoding.Unicode.GetPreamble()
            .Concat(System.Text.Encoding.Unicode.GetBytes(ValidManifest)).ToArray();

        ManifestReadResult result = await ReadBytesAsync(utf16);

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.EncodingUnsupported);
    }

    [Fact]
    public async Task Utf8_bom_is_accepted()
    {
        byte[] utf8Bom = { 0xEF, 0xBB, 0xBF };
        byte[] bytes = utf8Bom.Concat(System.Text.Encoding.UTF8.GetBytes(ValidManifest)).ToArray();

        ManifestReadResult result = await ReadBytesAsync(bytes);

        Assert.True(result.Valid);
    }

    [Fact]
    public async Task Manifest_larger_than_one_mebibyte_is_rejected()
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(ValidManifest)
            .Concat(System.Text.Encoding.UTF8.GetBytes(new string(' ', 1_048_577))).ToArray();

        ManifestReadResult result = await ReadBytesAsync(bytes);

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.TooLarge);
    }

    [Fact]
    public async Task Manifest_at_one_mebibyte_is_accepted()
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(ValidManifest);
        byte[] padded = body.Concat(new byte[1_048_576 - body.Length].Select(_ => (byte)' ')).ToArray();

        ManifestReadResult result = await ReadBytesAsync(padded);

        Assert.True(result.Valid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task Schema_version_must_be_exactly_one(int version)
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"schema_version\": 1,",
                $"\"schema_version\": {version},", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.SchemaVersionUnsupported
                && x.JsonPointer == "/schema_version");
    }

    [Fact]
    public async Task Strings_longer_than_2048_characters_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("synthetic-project",
                new string('a', 2_049), StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.StringTooLong && x.JsonPointer == "/asset_id");
    }

    [Fact]
    public async Task Strings_at_2048_characters_are_accepted()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("synthetic-project",
                new string('a', 2_048), StringComparison.Ordinal));

        Assert.True(result.Valid);
    }

    [Fact]
    public async Task More_than_1000_authorization_entries_are_rejected()
    {
        string entries = string.Join(", ", Enumerable.Range(0, 1_001)
            .Select(i => $"{{\"name\": \"lib-{i:0000}\", \"status\": \"verified\", \"reference\": null}}"));
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"third_party_authorizations\": []",
                $"\"third_party_authorizations\": [{entries}]", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.AuthorizationCountExceeded
                && x.JsonPointer == "/compliance_evidence/third_party_authorizations");
    }

    [Fact]
    public async Task One_thousand_authorization_entries_are_accepted()
    {
        string entries = string.Join(", ", Enumerable.Range(0, 1_000)
            .Select(i => $"{{\"name\": \"lib-{i:0000}\", \"status\": \"verified\", \"reference\": null}}"));
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"third_party_authorizations\": []",
                $"\"third_party_authorizations\": [{entries}]", StringComparison.Ordinal));

        Assert.True(result.Valid);
    }

    [Theory]
    [InlineData("..\\outside")]
    [InlineData("C:\\absolute")]
    [InlineData("/absolute")]
    [InlineData("a/../b")]
    [InlineData("//server/share")]
    public async Task Absolute_or_root_escape_paths_are_rejected(string path)
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"path\": \".\"",
                "\"path\": " + JsonSerializer.Serialize(path), StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.PathOutsideRoot && x.JsonPointer == "/components/0/path");
    }

    [Fact]
    public async Task Invalid_root_escape_fixture_is_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            await File.ReadAllTextAsync(FixturePath("invalid-root-escape.json"),
                TestContext.Current.CancellationToken));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.PathOutsideRoot && x.JsonPointer == "/components/0/path");
    }

    [Fact]
    public async Task Snapshot_sha256_is_deterministic_hash_of_original_bytes()
    {
        byte[] bytes = await File.ReadAllBytesAsync(FixturePath("valid-minimal.json"),
            TestContext.Current.CancellationToken);
        string expected = Convert.ToHexStringLower(SHA256.HashData(bytes));

        ManifestReadResult first = await ReadBytesAsync(bytes);
        ManifestReadResult second = await ReadBytesAsync(bytes);

        Assert.Equal(expected, first.Snapshot!.OriginalSha256);
        Assert.Equal(first.Snapshot.OriginalSha256, second.Snapshot!.OriginalSha256);
    }

    [Fact]
    public async Task Validation_errors_never_contain_offending_values()
    {
        const string secretMarker = "ASSET-SECRET-MARKER";
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("ASSET-009", secretMarker, StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.UnknownAssetType);
        Assert.DoesNotContain(result.Snapshot.Errors,
            x => x.Message.Contains(secretMarker, StringComparison.Ordinal)
                || x.JsonPointer.Contains(secretMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Comments_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"schema_version\": 1,",
                "// tampering marker\n  \"schema_version\": 1,", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.InvalidJson);
    }

    [Fact]
    public async Task Trailing_commas_are_rejected()
    {
        ManifestReadResult result = await ReadAsync(
            ValidManifest.Replace("\"asset_version\": \"1.0.0\",",
                "\"asset_version\": \"1.0.0\",,", StringComparison.Ordinal));

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.InvalidJson);
    }

    [Fact]
    public async Task Nesting_deeper_than_sixteen_levels_is_rejected()
    {
        string deep = string.Concat(Enumerable.Repeat("{\"a\": ", 20))
            + "1" + string.Concat(Enumerable.Repeat("}", 20));

        ManifestReadResult result = await ReadAsync(deep);

        Assert.True(result.Invalid);
        Assert.Contains(result.Snapshot!.Errors,
            x => x.Code == ManifestErrorCodes.InvalidJson);
    }

    [Fact]
    public void Schema_file_matches_the_reader_limits()
    {
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllText(SchemaPath()));
        JsonElement root = schema.RootElement;
        Assert.Equal(1, root.GetProperty("properties").GetProperty("schema_version")
            .GetProperty("const").GetInt32());
        Assert.False(root.GetProperty("additionalProperties").GetBoolean());
        Assert.Equal(JsonManifestReader.MaxStringLength,
            root.GetProperty("properties").GetProperty("asset_id").GetProperty("maxLength").GetInt32());
        Assert.Equal(AssetManifest.MaxComponents,
            root.GetProperty("properties").GetProperty("components").GetProperty("maxItems").GetInt32());
        Assert.Equal(ComplianceEvidence.MaxThirdPartyAuthorizations,
            root.GetProperty("properties").GetProperty("compliance_evidence")
                .GetProperty("properties").GetProperty("third_party_authorizations")
                .GetProperty("maxItems").GetInt32());
    }

    [Fact]
    public void Fixture_matches_the_source_generated_contract_shape()
    {
        using JsonDocument document = JsonDocument.Parse(
            File.ReadAllText(FixturePath("valid-minimal.json")));
        ManifestJsonDto dto = JsonSerializer.Deserialize(
            document.RootElement.GetRawText(), ManifestJsonContext.Default.ManifestJsonDto)!;

        Assert.Equal("synthetic-project", dto.AssetId);
        Assert.Equal(1, dto.SchemaVersion);
        Assert.Equal("ASSET-009", Assert.Single(dto.Components).AssetType);
        // The contract names are snake_case in both directions.
        string roundTrip = JsonSerializer.Serialize(dto, ManifestJsonContext.Default.ManifestJsonDto);
        Assert.Contains("\"schema_version\"", roundTrip, StringComparison.Ordinal);
        Assert.Contains("\"compliance_evidence\"", roundTrip, StringComparison.Ordinal);
        Assert.DoesNotContain("schemaVersion", roundTrip, StringComparison.Ordinal);
    }
}
