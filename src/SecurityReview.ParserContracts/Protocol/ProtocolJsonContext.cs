using System.Text.Json.Serialization;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;

namespace SecurityReview.ParserContracts.Protocol;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = false,
    MaxDepth = 32,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(ProtocolEnvelope))]
[JsonSerializable(typeof(ParseJob))]
[JsonSerializable(typeof(ParseLimits))]
[JsonSerializable(typeof(ContentChunk))]
[JsonSerializable(typeof(LocationMapEntry))]
[JsonSerializable(typeof(SourceLocator))]
[JsonSerializable(typeof(GapReason))]
[JsonSerializable(typeof(HelloPayload))]
public sealed partial class ProtocolJsonContext : JsonSerializerContext
{
}
