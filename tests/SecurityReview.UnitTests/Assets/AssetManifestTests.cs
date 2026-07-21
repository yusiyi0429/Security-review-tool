using SecurityReview.Domain.Assets;

namespace SecurityReview.UnitTests.Assets;

public sealed class AssetManifestTests
{
    [Theory]
    [InlineData("ASSET-001")]
    [InlineData("ASSET-011")]
    public void Accepts_registered_asset_type(string value) =>
        Assert.Equal(value, AssetTypeId.Parse(value).Value);

    [Theory]
    [InlineData("ASSET-000")]
    [InlineData("ASSET-012")]
    [InlineData("asset-001")]
    public void Rejects_unknown_asset_type(string value) =>
        Assert.Throws<ArgumentException>(() => AssetTypeId.Parse(value));

    [Theory]
    [InlineData("..\\outside")]
    [InlineData("C:\\absolute")]
    [InlineData("/absolute")]
    public void Rejects_component_path_outside_root(string path) =>
        Assert.Throws<ArgumentException>(() => AssetComponent.Create(path, AssetTypeId.Parse("ASSET-001")));

    [Theory]
    [InlineData("SENS-001")]
    [InlineData("SENS-008")]
    public void Accepts_registered_category(string value) =>
        Assert.Equal(value, CategoryId.Parse(value).Value);

    [Theory]
    [InlineData("SENS-000")]
    [InlineData("SENS-009")]
    [InlineData("sens-001")]
    public void Rejects_unknown_category(string value) =>
        Assert.Throws<ArgumentException>(() => CategoryId.Parse(value));

    [Fact]
    public void Schema_version_is_exactly_one() =>
        Assert.Equal(1, AssetManifest.SchemaVersion);

    [Fact]
    public void Rejects_empty_component_list() =>
        Assert.Throws<ArgumentException>(() => AssetManifest.Create(
            "asset", "1.0.0", [], SampleEvidence()));

    [Fact]
    public void Rejects_empty_asset_id() =>
        Assert.Throws<ArgumentException>(() => AssetManifest.Create(
            " ", "1.0.0", [SampleComponent()], SampleEvidence()));

    [Fact]
    public void Rejects_empty_asset_version() =>
        Assert.Throws<ArgumentException>(() => AssetManifest.Create(
            "asset", "", [SampleComponent()], SampleEvidence()));

    [Fact]
    public void Rejects_duplicate_component_paths_case_insensitively() =>
        Assert.Throws<ArgumentException>(() => AssetManifest.Create(
            "asset", "1.0.0",
            [AssetComponent.Create("Src/File.cs", AssetTypeId.Parse("ASSET-001")),
                AssetComponent.Create("src/file.cs", AssetTypeId.Parse("ASSET-002"))],
            SampleEvidence()));

    [Fact]
    public void Rejects_nested_component_paths_that_overlap() =>
        Assert.Throws<ArgumentException>(() => AssetManifest.Create(
            "asset", "1.0.0",
            [AssetComponent.Create("src", AssetTypeId.Parse("ASSET-001")),
                AssetComponent.Create("src/generated", AssetTypeId.Parse("ASSET-002"))],
            SampleEvidence()));

    [Fact]
    public void Accepts_sibling_component_paths() =>
        Assert.Equal(2, AssetManifest.Create(
            "asset", "1.0.0",
            [AssetComponent.Create("src", AssetTypeId.Parse("ASSET-001")),
                AssetComponent.Create("docs", AssetTypeId.Parse("ASSET-002"))],
            SampleEvidence()).Components.Count);

    [Fact]
    public void Root_component_accepts_dot_path() =>
        Assert.Equal(".", AssetComponent.Create(".", AssetTypeId.Parse("ASSET-001")).RelativePath);

    [Fact]
    public void Compliance_declaration_never_suppresses_content_scanning()
    {
        // Scan suppression must not be representable: no member on the manifest
        // or evidence types may carry a suppression/skip flag, and the scan
        // requirement is a constant instead of settable state.
        Assert.True(AssetManifest.RequiresContentScanning);
        foreach (Type type in new[]
        {
            typeof(AssetManifest), typeof(AssetComponent), typeof(ComplianceEvidence),
            typeof(ComplianceDeclaration), typeof(ThirdPartyAuthorization)
        })
        {
            Assert.DoesNotContain(type.GetProperties(), property =>
                property.Name.Contains("suppress", StringComparison.OrdinalIgnoreCase)
                || property.Name.Contains("skip", StringComparison.OrdinalIgnoreCase));
        }
    }

    private static AssetComponent SampleComponent() =>
        AssetComponent.Create(".", AssetTypeId.Parse("ASSET-001"));

    private static ComplianceEvidence SampleEvidence() => ComplianceEvidence.Create(
        new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
        new ComplianceDeclaration(ComplianceEvidenceStatus.NotApplicable, null),
        []);
}
