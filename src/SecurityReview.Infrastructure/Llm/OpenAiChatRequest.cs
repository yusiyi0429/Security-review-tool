using System.Buffers;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Llm;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Renders the bounded request payload for a single semantic-review
/// LLM call.
///
/// The request shape is fixed: a <c>model</c> field plus exactly two
/// messages (system + user). The system message is loaded from the
/// pinned <c>semantic-review-v1.txt</c> template; the user message is
/// a serialized JSON envelope carrying the bounded candidate payload
/// produced by <see cref="CandidateMinimizer"/>. Optional
/// <c>temperature</c> and <c>response_format</c> fields are emitted
/// based on the supplied <see cref="LlmEndpointOptions"/> — the parser
/// on the response side is shared across all three
/// <see cref="LlmResponseFormatMode"/> modes.
///
/// The builder refuses to emit a request whose UTF-8 byte length
/// exceeds <see cref="MaxRequestBytes"/>. The check is performed on
/// the final serialized payload so prompt / schema overhead cannot
/// silently inflate the request past the wire ceiling.
/// </summary>
public static class OpenAiChatRequest
{
    /// <summary>Maximum UTF-8 byte length of the rendered request.</summary>
    public const int MaxRequestBytes = 65_536;

    /// <summary>UTF-8 byte ceiling for the candidate portion of the request.</summary>
    public const int MaxCandidateBytes = 16 * 1024;

    /// <summary>Pinned template name (and the literal "PromptVersion" value).</summary>
    public const string PromptVersion = "semantic-review-v1";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly Lazy<(string Text, string Sha256)> PromptResource = new(LoadPromptResource);

    /// <summary>
    /// Loads the pinned prompt template. The text is embedded as an
    /// MSBuild resource at compile time so the build is the only
    /// place a developer can change the prompt — runtime editing is
    /// impossible.
    /// </summary>
    public static (string Text, string Sha256) PromptTemplate => PromptResource.Value;

    /// <summary>
    /// Serialize the candidate payload into the full request JSON.
    /// Throws <see cref="LlmRequestContractOversizeException"/> if the
    /// rendered request exceeds <see cref="MaxRequestBytes"/>.
    /// </summary>
    public static byte[] Build(
        LlmEndpointOptions options,
        MinimizedCandidate candidate,
        string? correlationId = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(candidate);

        if (candidate.PackedUtf8ByteLength > MaxCandidateBytes)
            throw new LlmRequestContractOversizeException(
                $"Candidate payload exceeds {MaxCandidateBytes} bytes " +
                $"(was {candidate.PackedUtf8ByteLength}).");

        string systemText = PromptTemplate.Text;
        string userJson = JsonSerializer.Serialize(
            BuildUserEnvelope(candidate),
            JsonOptions);

        object responseFormat = options.ResponseFormatMode switch
        {
            LlmResponseFormatMode.JsonSchema => new
            {
                type = "json_schema",
                json_schema = new
                {
                    name = "semantic_review_response",
                    schema = LoadSchemaResource(),
                    strict = true,
                },
            },
            LlmResponseFormatMode.JsonObject => new { type = "json_object" },
            _ => null!,
        };

        var body = new Dictionary<string, object?>
        {
            ["model"] = options.Model,
            ["messages"] = new object[]
            {
                new { role = "system", content = systemText },
                new { role = "user", content = userJson },
            },
        };
        if (options.SendTemperatureZero)
            body["temperature"] = 0;
        if (options.ResponseFormatMode != LlmResponseFormatMode.PromptOnly)
            body["response_format"] = responseFormat;

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body, JsonOptions);
        if (bytes.Length > MaxRequestBytes)
            throw new LlmRequestContractOversizeException(
                $"Rendered request is {bytes.Length} bytes; ceiling is {MaxRequestBytes}.");

        // The user envelope must remain ≤ the candidate ceiling; a
        // contraction of the system text could otherwise let the user
        // side drift upward. Re-measure after the envelope is fixed.
        int userEnvelopeBytes = Encoding.UTF8.GetByteCount(userJson);
        if (userEnvelopeBytes > MaxCandidateBytes)
            throw new LlmRequestContractOversizeException(
                $"User envelope is {userEnvelopeBytes} bytes; ceiling is {MaxCandidateBytes}.");

        return bytes;
    }

    private static Dictionary<string, object?> BuildUserEnvelope(MinimizedCandidate c)
    {
        return new Dictionary<string, object?>
        {
            ["candidate_id"] = c.CandidateId.Value.ToString("D"),
            ["category_hint"] = c.CategoryHint.Value,
            ["content_kind"] = c.ContentKind,
            ["extension"] = c.Extension,
            ["untrusted_context"] = c.UntrustedContext,
            ["candidate_value"] = c.RedactedCandidateValue,
            ["truncation"] = new Dictionary<string, object?>
            {
                ["left_truncated_bytes"] = c.ContextLeftTruncatedBytes,
                ["right_truncated_bytes"] = c.ContextRightTruncatedBytes,
                ["truncated"] = c.ContextTruncated,
                ["redactions"] = c.SecretRedactions,
            },
        };
    }

    private static JsonElement LoadSchemaResource()
    {
        // The schema is embedded as an MSBuild resource at compile
        // time. The bytes are parsed once per process.
        return JsonDocument.Parse(LoadSchemaText()).RootElement.Clone();
    }

    private static string LoadSchemaText()
    {
        Assembly asm = typeof(OpenAiChatRequest).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("semantic-review-response-v1.schema.json", StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                "Response schema resource is missing from the assembly.");

        using Stream? stream = asm.GetManifestResourceStream(resourceName);
        if (stream is null)
            throw new InvalidOperationException(
                "Failed to open response schema resource stream.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static (string Text, string Sha256) LoadPromptResource()
    {
        Assembly asm = typeof(OpenAiChatRequest).Assembly;
        string resourceName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("Prompts.semantic-review-v1.txt", StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                "Prompt template resource is missing from the assembly.");

        using Stream? stream = asm.GetManifestResourceStream(resourceName);
        if (stream is null)
            throw new InvalidOperationException(
                "Failed to open prompt template resource stream.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        string text = reader.ReadToEnd();
        return (text, ComputeSha256(text));
    }

    private static string ComputeSha256(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

/// <summary>
/// Thrown when the rendered request payload cannot fit the wire byte
/// ceiling. The caller treats this as a hard failure (no truncation,
/// no structural change) and surfaces
/// <c>llm_request_contract_oversize</c> as the diagnostic reason.
/// </summary>
public sealed class LlmRequestContractOversizeException : InvalidOperationException
{
    public LlmRequestContractOversizeException(string message) : base(message) { }
}
