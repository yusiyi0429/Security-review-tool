using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;

namespace SecurityReview.RulePack.Schema;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = false,
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(RulePackDocument))]
[JsonSerializable(typeof(RuleDefinition))]
[JsonSerializable(typeof(DetectorDefinition))]
[JsonSerializable(typeof(CategoryDefinition))]
[JsonSerializable(typeof(AssetPolicy))]
[JsonSerializable(typeof(ComplianceRule))]
[JsonSerializable(typeof(FindingKind))]
[JsonSerializable(typeof(Severity))]
[JsonSerializable(typeof(DetectionConfidence))]
[JsonSerializable(typeof(DetectorKind))]
[JsonSerializable(typeof(IReadOnlyList<CategoryDefinition>))]
[JsonSerializable(typeof(IReadOnlyList<AssetPolicy>))]
[JsonSerializable(typeof(IReadOnlyList<DetectorDefinition>))]
[JsonSerializable(typeof(IReadOnlyList<ComplianceRule>))]
[JsonSerializable(typeof(IReadOnlyList<RuleDefinition>))]
public sealed partial class RulePackJsonContext : JsonSerializerContext
{
}
