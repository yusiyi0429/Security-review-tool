using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityReview.Infrastructure.Manifest;

// Contract shape of security-asset-manifest.json. The strict reader
// (JsonManifestReader) parses manually to enforce duplicate tracking, unknown
// field rejection and size bounds; this source-generated context pins the
// snake_case property names and is used by the contract tests to verify the
// wire shape, and by rules/schemas/security-asset-manifest-v1.schema.json.
public sealed class ManifestJsonDto
{
    public required int SchemaVersion { get; init; }

    public required string AssetId { get; init; }

    public required string AssetVersion { get; init; }

    public required IReadOnlyList<ManifestComponentJsonDto> Components { get; init; }

    public required ManifestEvidenceJsonDto ComplianceEvidence { get; init; }
}

public sealed class ManifestComponentJsonDto
{
    public required string Path { get; init; }

    public required string AssetType { get; init; }
}

public sealed class ManifestEvidenceJsonDto
{
    public required ManifestDeclarationJsonDto KnowledgeBaseTransformed { get; init; }

    public required ManifestDeclarationJsonDto ModelFinetuned { get; init; }

    public required IReadOnlyList<ManifestAuthorizationJsonDto> ThirdPartyAuthorizations { get; init; }
}

public sealed class ManifestDeclarationJsonDto
{
    public required string Status { get; init; }

    public string? Reference { get; init; }
}

public sealed class ManifestAuthorizationJsonDto
{
    public required string Name { get; init; }

    public required string Status { get; init; }

    public string? Reference { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    ReadCommentHandling = JsonCommentHandling.Disallow,
    AllowTrailingCommas = false)]
[JsonSerializable(typeof(ManifestJsonDto))]
public sealed partial class ManifestJsonContext : JsonSerializerContext;
