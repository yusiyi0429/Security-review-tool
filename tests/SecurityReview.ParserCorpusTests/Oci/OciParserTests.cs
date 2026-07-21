namespace SecurityReview.ParserCorpusTests.Oci;

using SecurityReview.Parsers.Oci;

public sealed class OciParserTests
{
    private static readonly string CorpusRoot = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "Corpus", "Oci");

    [Fact]
    public void oci_digest_parse_golden_digests()
    {
        string goldenPath = Path.Combine(CorpusRoot, "oci-golden.json");
        Assert.True(File.Exists(goldenPath), $"Golden file not found: {goldenPath}");

        string json = File.ReadAllText(goldenPath);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;

        string configDigest = root.GetProperty("config_digest").GetString()!;
        string manifestDigest = root.GetProperty("manifest_digest").GetString()!;
        string layer1Digest = root.GetProperty("layer1_digest").GetString()!;
        string layer2Digest = root.GetProperty("layer2_digest").GetString()!;

        var c = OciDigest.Parse(configDigest);
        var m = OciDigest.Parse(manifestDigest);
        var l1 = OciDigest.Parse(layer1Digest);
        var l2 = OciDigest.Parse(layer2Digest);

        Assert.StartsWith("sha256:", c.Value);
        Assert.StartsWith("sha256:", m.Value);
        Assert.StartsWith("sha256:", l1.Value);
        Assert.StartsWith("sha256:", l2.Value);
        Assert.Equal(32, c.Hash.Length);
        Assert.Equal(32, m.Hash.Length);
        Assert.Equal(32, l1.Hash.Length);
        Assert.Equal(32, l2.Hash.Length);
    }

    [Fact]
    public void parse_oci_index_json()
    {
        string indexPath = Path.Combine(CorpusRoot, "oci-layout", "index.json");
        Assert.True(File.Exists(indexPath), $"Index not found: {indexPath}");

        byte[] json = File.ReadAllBytes(indexPath);
        var index = OciJsonParser.ParseIndex(json, indexPath);

        Assert.Equal(2, index.SchemaVersion);
        Assert.Contains("index", index.MediaType);
        Assert.True(index.Manifests.Count >= 2);

        // Check multi-platform preservation
        var platforms = index.Manifests
            .Where(m => m.Platform != null)
            .Select(m => m.Platform!.Architecture)
            .ToList();
        Assert.Contains("amd64", platforms);
        Assert.Contains("arm64", platforms);
    }

    [Fact]
    public void parse_oci_layout_version()
    {
        string layoutPath = Path.Combine(CorpusRoot, "oci-layout", "oci-layout");
        Assert.True(File.Exists(layoutPath), $"oci-layout not found: {layoutPath}");

        string json = File.ReadAllText(layoutPath);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        string version = doc.RootElement.GetProperty("imageLayoutVersion").GetString()!;
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void verify_blob_exists_for_each_descriptor()
    {
        string indexPath = Path.Combine(CorpusRoot, "oci-layout", "index.json");
        byte[] json = File.ReadAllBytes(indexPath);
        var index = OciJsonParser.ParseIndex(json, indexPath);

        string blobsDir = Path.Combine(CorpusRoot, "oci-layout", "blobs", "sha256");

        foreach (var descriptor in index.Manifests)
        {
            // Skip the deliberately missing blob
            if (descriptor.Digest.Contains("0000000000000000"))
            {
                string corruptHex = descriptor.Digest.Substring("sha256:".Length);
                string corruptPath = Path.Combine(blobsDir, corruptHex);
                Assert.False(File.Exists(corruptPath),
                    $"Missing blob should not exist: {corruptPath}");
                continue;
            }

            string hex = descriptor.Digest.Substring("sha256:".Length);
            string blobPath = Path.Combine(blobsDir, hex);
            Assert.True(File.Exists(blobPath),
                $"Blob should exist: {blobPath}");
        }
    }

    [Fact]
    public void parse_manifest_json_from_blob()
    {
        string goldenPath = Path.Combine(CorpusRoot, "oci-golden.json");
        string golden = File.ReadAllText(goldenPath);
        using var doc = System.Text.Json.JsonDocument.Parse(golden);
        string manifestDigest = doc.RootElement.GetProperty("manifest_digest").GetString()!;
        string manifestHex = manifestDigest.Substring("sha256:".Length);

        string blobPath = Path.Combine(CorpusRoot, "oci-layout", "blobs", "sha256", manifestHex);
        Assert.True(File.Exists(blobPath));

        byte[] json = File.ReadAllBytes(blobPath);
        var manifest = OciJsonParser.ParseManifest(json, blobPath);

        Assert.Equal(2, manifest.SchemaVersion);
        Assert.NotNull(manifest.Config);
        Assert.Equal(2, manifest.Layers.Count);

        // Verify config descriptor
        Assert.NotNull(manifest.Config.Digest);
        Assert.True(manifest.Config.Size > 0);

        // Verify layer descriptors
        foreach (var layer in manifest.Layers)
        {
            Assert.NotNull(layer.Digest);
            Assert.True(layer.Size > 0);
            Assert.Contains("tar", layer.MediaType);
        }
    }

    [Fact]
    public void parse_config_json_from_blob()
    {
        string goldenPath = Path.Combine(CorpusRoot, "oci-golden.json");
        string golden = File.ReadAllText(goldenPath);
        using var doc = System.Text.Json.JsonDocument.Parse(golden);
        string configDigest = doc.RootElement.GetProperty("config_digest").GetString()!;
        string configHex = configDigest.Substring("sha256:".Length);

        string blobPath = Path.Combine(CorpusRoot, "oci-layout", "blobs", "sha256", configHex);
        Assert.True(File.Exists(blobPath));

        byte[] json = File.ReadAllBytes(blobPath);
        var config = OciJsonParser.ParseConfig(json, blobPath);

        Assert.Equal("amd64", config.Architecture);
        Assert.Equal("linux", config.Os);
        Assert.NotEmpty(config.Env);
        Assert.NotEmpty(config.Labels);
        Assert.NotNull(config.Entrypoint);
        Assert.NotNull(config.Cmd);
        Assert.Equal("/app", config.WorkingDir);
        Assert.Equal("1000:1000", config.User);
        Assert.Contains("8080/tcp", config.ExposedPorts);
        Assert.Contains("/data", config.Volumes);
        Assert.NotEmpty(config.RootfsDiffIds);
        Assert.NotEmpty(config.History);

        // Verify history entries
        foreach (var entry in config.History)
        {
            Assert.NotNull(entry.CreatedBy);
        }
    }

    [Fact]
    public void whiteout_classifier_detects_individual_whiteout()
    {
        var result = WhiteoutClassifier.Classify(".wh.canary.txt",
            System.Formats.Tar.TarEntryType.RegularFile);

        Assert.Equal(WhiteoutKind.Individual, result.Kind);
        Assert.Equal("canary.txt", result.DeletedTarget);
    }

    [Fact]
    public void whiteout_classifier_detects_opaque_whiteout()
    {
        var result = WhiteoutClassifier.Classify(".wh..wh..opq",
            System.Formats.Tar.TarEntryType.RegularFile);

        Assert.Equal(WhiteoutKind.Opaque, result.Kind);
    }

    [Fact]
    public void whiteout_classifier_ignores_normal_file()
    {
        var result = WhiteoutClassifier.Classify("keep-me.txt",
            System.Formats.Tar.TarEntryType.RegularFile);

        Assert.Equal(WhiteoutKind.None, result.Kind);
        Assert.Null(result.DeletedTarget);
    }

    [Fact]
    public void whiteout_classifier_handles_nested_whiteout()
    {
        var result = WhiteoutClassifier.Classify("dir/.wh.config",
            System.Formats.Tar.TarEntryType.RegularFile);

        Assert.Equal(WhiteoutKind.Individual, result.Kind);
        Assert.Equal("dir/config", result.DeletedTarget);
    }

    [Fact]
    public void parse_corrupt_index_with_missing_blobs()
    {
        string corruptIndexPath = Path.Combine(CorpusRoot, "oci-layout", "corrupt-index.json");
        Assert.True(File.Exists(corruptIndexPath));

        byte[] json = File.ReadAllBytes(corruptIndexPath);
        var index = OciJsonParser.ParseIndex(json, corruptIndexPath);

        Assert.Single(index.Manifests);
        var descriptor = index.Manifests[0];

        // The blob should exist (manifest itself exists) but its referenced
        // config blob (corrupt) has wrong size
        string hex = descriptor.Digest.Substring("sha256:".Length);
        string blobPath = Path.Combine(CorpusRoot, "oci-layout", "blobs", "sha256", hex);
        Assert.True(File.Exists(blobPath));
    }

    [Fact]
    public void compute_golden_layer_diff_ids()
    {
        // Diff IDs in config are sha256 of the uncompressed layer tar
        string goldenPath = Path.Combine(CorpusRoot, "oci-golden.json");
        string golden = File.ReadAllText(goldenPath);
        using var doc = System.Text.Json.JsonDocument.Parse(golden);
        var root = doc.RootElement;

        string layer1DiffId = root.GetProperty("layer1_diff_id").GetString()!;
        string layer2DiffId = root.GetProperty("layer2_diff_id").GetString()!;

        var d1 = OciDigest.Parse(layer1DiffId);
        var d2 = OciDigest.Parse(layer2DiffId);

        Assert.Equal(32, d1.Hash.Length);
        Assert.Equal(32, d2.Hash.Length);
        Assert.NotEqual(d1, d2);
    }
}
