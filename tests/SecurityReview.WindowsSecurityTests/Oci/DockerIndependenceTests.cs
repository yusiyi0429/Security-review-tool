namespace SecurityReview.WindowsSecurityTests.Oci;

/// <summary>
/// Verifies that the Docker/OCI parsers never contact or reference
/// Docker Desktop, daemon sockets, or standard Docker locations.
/// </summary>
public sealed class DockerIndependenceTests
{
    private static readonly string[] DockerPaths =
    [
        "/var/run/docker.sock",
        "/var/run/docker",
        "/run/docker",
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/var/lib/docker",
        "/etc/docker",
        "/.dockerenv",
    ];

    private static readonly string[] DockerEnvVars =
    [
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "DOCKER_API_VERSION",
    ];

    private static readonly string[] ForbiddenPatterns =
    [
        "HttpClient",
        "Socket",
        "Registry",
        "Daemon",
    ];

    [Fact]
    public void docker_archive_parser_does_not_use_daemon_socket_or_registry()
    {
        string source = ReadSourceFile("src/SecurityReview.Parsers/Oci/DockerArchiveParser.cs");

        // The parser should not reference Docker API, sockets, or registries
        foreach (string pattern in ForbiddenPatterns)
        {
            Assert.False(source.Contains(pattern, StringComparison.Ordinal),
                $"DockerArchiveParser should not contain '{pattern}'");
        }

        // "Docker" keyword is only in class name — remove it and verify
        string noClass = source.Replace("DockerArchiveParser", "");
        Assert.False(noClass.Contains("Docker", StringComparison.Ordinal),
            "DockerArchiveParser should not reference Docker beyond its own class name");
    }

    [Fact]
    public void oci_layer_parser_does_not_use_daemon_socket_or_registry()
    {
        string source = ReadSourceFile("src/SecurityReview.Parsers/Oci/OciLayerParser.cs");

        foreach (string pattern in ForbiddenPatterns)
        {
            Assert.False(source.Contains(pattern, StringComparison.Ordinal),
                $"OciLayerParser should not contain '{pattern}'");
        }
    }

    [Fact]
    public void oci_layout_planner_uses_blob_paths_not_urls()
    {
        string source = ReadSourceFile("src/SecurityReview.Application/Scans/Oci/OciLayoutPlanner.cs");

        // Should derive blob paths from digest, never fetch URLs
        Assert.True(source.Contains("DeriveBlobPath", StringComparison.Ordinal));
        Assert.True(source.Contains("blobs/sha256", StringComparison.Ordinal));

        string[] urlPatterns = { "HttpClient", "WebClient", "Fetch", "Download" };
        foreach (string pattern in urlPatterns)
        {
            Assert.False(source.Contains(pattern, StringComparison.Ordinal),
                $"OciLayoutPlanner should not contain '{pattern}'");
        }
    }

    [Fact]
    public void no_standard_docker_paths_accessed()
    {
        foreach (string fileName in new[] { "OciDigest.cs", "OciJsonParser.cs",
            "DockerArchiveParser.cs", "OciLayerParser.cs", "WhiteoutClassifier.cs" })
        {
            string content = ReadSourceFile($"src/SecurityReview.Parsers/Oci/{fileName}");
            foreach (string dockerPath in DockerPaths)
            {
                Assert.False(content.Contains(dockerPath, StringComparison.Ordinal),
                    $"{fileName} should not reference {dockerPath}");
            }
        }
    }

    [Fact]
    public void no_docker_env_vars_read_by_oci_parsers()
    {
        foreach (string fileName in new[] { "OciDigest.cs", "OciJsonParser.cs",
            "DockerArchiveParser.cs", "OciLayerParser.cs", "WhiteoutClassifier.cs" })
        {
            string content = ReadSourceFile($"src/SecurityReview.Parsers/Oci/{fileName}");
            foreach (string envVar in DockerEnvVars)
            {
                Assert.False(content.Contains(envVar, StringComparison.Ordinal),
                    $"{fileName} should not read {envVar}");
            }
        }
    }

    [Fact]
    public void oci_descriptor_url_is_metadata_only()
    {
        string descriptorSource = ReadSourceFile("src/SecurityReview.Domain/Assets/OciDescriptor.cs");

        Assert.True(descriptorSource.Contains("never fetched", StringComparison.Ordinal));
        Assert.True(descriptorSource.Contains("metadata-only", StringComparison.Ordinal));
    }

    private static string ReadSourceFile(string relativePath)
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string fullPath = Path.GetFullPath(Path.Combine(baseDir, "../../../../", relativePath));
        return File.ReadAllText(fullPath);
    }
}
