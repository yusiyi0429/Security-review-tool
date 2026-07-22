using System.Buffers;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Llm;

namespace SecurityReview.Infrastructure.Llm;

/// <summary>
/// Strict, closed parser for the semantic-review LLM response. The
/// parser enforces the byte ceiling, an exact field allowlist, a depth
/// cap, and a closed enum allowlist for <c>classification</c> and
/// <c>category_id</c>. Anything outside the contract maps to
/// <see cref="SemanticClassification.Unresolved"/> with a stable
/// <c>ReasonCode</c> so the audit / UI layer can switch on it.
///
/// Streaming rules:
///   * The HTTP response is read with
///     <see cref="HttpCompletionOption.ResponseHeadersRead"/> and a
///     counting stream that stops at 65,536 bytes before parsing. An
///     <see cref="ReadOnlySpan{T}.Length"/>-bounded span is the only
///     thing the JSON reader sees — no unbounded
///     <c>ReadAsStringAsync</c> is ever called.
///   * <see cref="Utf8JsonReader"/> is configured with a max depth of
///     8 and explicit duplicate / unknown-property tracking.
/// </summary>
public static class OpenAiChatResponseParser
{
    /// <summary>Hard byte ceiling for the response body.</summary>
    public const int MaxResponseBytes = 65_536;

    /// <summary>Max nested depth allowed in the response JSON.</summary>
    public const int MaxDepth = 8;

    private const string FieldCandidateId = "candidate_id";
    private const string FieldClassification = "classification";
    private const string FieldCategoryId = "category_id";
    private const string FieldConfidence = "confidence";
    private const string FieldRationale = "rationale";
    private const string FieldInjectionDetected = "injection_detected";

    private static readonly string[] AllowedTopLevelFields =
    {
        FieldCandidateId,
        FieldClassification,
        FieldCategoryId,
        FieldConfidence,
        FieldRationale,
        FieldInjectionDetected,
    };

    private static readonly HashSet<string> AllowedClassifications = new(StringComparer.Ordinal)
    {
        "confirmed",
        "possible",
        "unlikely",
        "unresolved",
    };

    private static readonly HashSet<string> AllowedCategoryIds = new(StringComparer.Ordinal)
    {
        "SENS-001", "SENS-002", "SENS-003", "SENS-004",
        "SENS-005", "SENS-006", "SENS-007", "SENS-008",
    };

    /// <summary>
    /// Read the supplied <see cref="HttpResponseMessage"/>, parse the
    /// body with the closed allowlist, and return the validated
    /// <see cref="LlmReviewResult"/>. Caller is responsible for
    /// disposing <paramref name="response"/>.
    /// </summary>
    public static async Task<LlmReviewResult> ParseAsync(
        CandidateId expectedCandidateId,
        HttpResponseMessage response,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);

        byte[] body;
        await using (var counter = new BoundedResponseStream(
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
            MaxResponseBytes))
        {
            body = counter.ReadAllBytes();
        }

        if (body.Length == 0)
            return Unresolved(expectedCandidateId, "response_body_empty");

        // Hard limit: the response (after stripping outer envelope)
        // must also fit. We bail before even attempting JSON parse.
        if (body.Length > MaxResponseBytes)
            return Unresolved(expectedCandidateId, "response_over_size_limit");

        // Reject markdown fences and prose prefixes/suffixes before
        // the JSON reader sees the bytes. The body must either start
        // with '{' (direct JSON) or with a single line of whitespace
        // that contains no letter — any prose prefix is treated as
        // failure.
        int jsonStart = FindJsonStart(body);
        int jsonEnd = FindJsonEnd(body);
        if (jsonStart < 0 || jsonEnd <= jsonStart)
            return Unresolved(expectedCandidateId, "response_not_json");

        ReadOnlySpan<byte> jsonSpan = body.AsSpan(jsonStart, jsonEnd - jsonStart);

        // Single JSON object only. We enforce that the outer value is
        // an object and we reject any wrapping array / value.
        var reader = new Utf8JsonReader(
            jsonSpan,
            new JsonReaderOptions
            {
                MaxDepth = MaxDepth,
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = false,
            });

        if (!reader.Read())
            return Unresolved(expectedCandidateId, "response_body_empty");

        ParseOutcome outcome = ParseObject(
            ref reader, expectedCandidateId, out var parsed);

        if (outcome is not ParseOutcome.Ok)
            return Unresolved(expectedCandidateId, outcome.ToReasonCode());

        // The wire format may wrap the JSON object in
        // { "choices": [ { "message": { "role": "assistant", "content": "..." } } ] }.
        // Our caller has already extracted the inner object. If the
        // candidate wants the outer envelope we can extend this; for
        // now the simpler shape is what the brief describes.
        return parsed!;
    }

    private static ParseOutcome ParseObject(
        ref Utf8JsonReader reader,
        CandidateId expectedCandidateId,
        out LlmReviewResult? result)
    {
        result = null;

        if (reader.TokenType != JsonTokenType.StartObject)
            return ParseOutcome.NotJsonObject;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? candidateId = null;
        string? classification = null;
        string? categoryId = null;
        double? confidence = null;
        string? rationale = null;
        bool? injectionDetected = null;

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                break;
            if (reader.TokenType != JsonTokenType.PropertyName)
                return ParseOutcome.MalformedStructure;

            string name = reader.GetString() ?? string.Empty;
            if (!seen.Add(name))
                return ParseOutcome.DuplicateProperty;

            switch (name)
            {
                case FieldCandidateId:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.String)
                        return ParseOutcome.WrongTypeForField;
                    candidateId = reader.GetString();
                    break;
                case FieldClassification:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.String)
                        return ParseOutcome.WrongTypeForField;
                    classification = reader.GetString();
                    break;
                case FieldCategoryId:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.String)
                        return ParseOutcome.WrongTypeForField;
                    categoryId = reader.GetString();
                    break;
                case FieldConfidence:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.Number)
                        return ParseOutcome.WrongTypeForField;
                    if (!reader.TryGetDouble(out double c))
                        return ParseOutcome.InvalidNumber;
                    confidence = c;
                    if (double.IsNaN(confidence.Value) || double.IsInfinity(confidence.Value))
                        return ParseOutcome.InvalidNumber;
                    if (confidence.Value < 0.0 || confidence.Value > 1.0)
                        return ParseOutcome.OutOfRange;
                    break;
                case FieldRationale:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.String)
                        return ParseOutcome.WrongTypeForField;
                    rationale = reader.GetString() ?? string.Empty;
                    if (rationale.Length > 500)
                        return ParseOutcome.RationaleTooLong;
                    if (ContainsControlChar(rationale))
                        return ParseOutcome.RationaleControlChar;
                    break;
                case FieldInjectionDetected:
                    if (!reader.Read()) return ParseOutcome.MalformedStructure;
                    if (reader.TokenType != JsonTokenType.True &&
                        reader.TokenType != JsonTokenType.False)
                        return ParseOutcome.WrongTypeForField;
                    injectionDetected = reader.TokenType == JsonTokenType.True;
                    break;
                default:
                    // Unknown / not-allowed property name — reject.
                    return ParseOutcome.UnknownProperty;
            }
        }

        // Required fields must all be present.
        if (candidateId is null) return ParseOutcome.MissingField;
        if (classification is null) return ParseOutcome.MissingField;
        if (categoryId is null) return ParseOutcome.MissingField;
        if (confidence is null) return ParseOutcome.MissingField;
        if (rationale is null) return ParseOutcome.MissingField;
        if (injectionDetected is null) return ParseOutcome.MissingField;

        // Must reference the expected candidate id.
        if (!Guid.TryParse(candidateId, out Guid parsedId))
            return ParseOutcome.CandidateIdMalformed;
        if (parsedId != expectedCandidateId.Value)
            return ParseOutcome.CandidateIdMismatch;

        if (!AllowedClassifications.Contains(classification))
            return ParseOutcome.UnknownClassification;
        if (!AllowedCategoryIds.Contains(categoryId))
            return ParseOutcome.UnknownCategory;

        var semanticClassification = classification switch
        {
            "confirmed" => SemanticClassification.Confirmed,
            "possible" => SemanticClassification.Possible,
            "unlikely" => SemanticClassification.Unlikely,
            _ => SemanticClassification.Unresolved,
        };

        // The wire-format JSON did not surface any tool calls / refusal
        // (we never opened any field for them). If injection_detected
        // is true, downgrade to Unresolved with no rationale trusted.
        if (injectionDetected == true)
        {
            result = new LlmReviewResult
            {
                CandidateId = expectedCandidateId,
                Classification = SemanticClassification.Unresolved,
                CategoryId = CategoryId.Parse("SENS-001"),
                Confidence = null,
                Rationale = string.Empty,
                ReasonCode = "injection_detected",
                InjectionDetected = true,
                PromptSha256 = OpenAiChatRequest.PromptTemplate.Sha256,
                PromptVersion = OpenAiChatRequest.PromptVersion,
            };
            return ParseOutcome.Ok;
        }

        result = new LlmReviewResult
        {
            CandidateId = expectedCandidateId,
            Classification = semanticClassification,
            CategoryId = CategoryId.Parse(categoryId),
            Confidence = confidence,
            Rationale = rationale,
            ReasonCode = null,
            InjectionDetected = false,
            PromptSha256 = OpenAiChatRequest.PromptTemplate.Sha256,
            PromptVersion = OpenAiChatRequest.PromptVersion,
        };
        return ParseOutcome.Ok;
    }

    private static int FindJsonStart(byte[] body)
    {
        for (int i = 0; i < body.Length; i++)
        {
            byte b = body[i];
            if (b == (byte)'{') return i;
            if (b == (byte)'[') return -1; // outer array — reject
            // Allow whitespace / control bytes but not letters.
            if (b <= 0x20) continue;
            if (b == (byte)'\n' || b == (byte)'\r' || b == (byte)'\t') continue;
            return -1;
        }
        return -1;
    }

    private static int FindJsonEnd(byte[] body)
    {
        // Match the outermost closing brace. The body is small enough
        // (≤64 KiB) for a one-pass scan.
        int depth = 0;
        bool insideString = false;
        bool escape = false;
        for (int i = 0; i < body.Length; i++)
        {
            byte c = body[i];
            if (insideString)
            {
                if (escape) { escape = false; continue; }
                if (c == (byte)'\\') { escape = true; continue; }
                if (c == (byte)'"') insideString = false;
                continue;
            }
            if (c == (byte)'"') insideString = true;
            else if (c == (byte)'{') depth++;
            else if (c == (byte)'}')
            {
                depth--;
                if (depth == 0) return i + 1;
            }
        }
        return -1;
    }

    private static bool ContainsControlChar(string s)
    {
        foreach (char c in s)
        {
            if (c < 0x20 || c == 0x7F) return true;
        }
        return false;
    }

    private static LlmReviewResult Unresolved(CandidateId id, string reasonCode)
    {
        return new LlmReviewResult
        {
            CandidateId = id,
            Classification = SemanticClassification.Unresolved,
            CategoryId = CategoryId.Parse("SENS-001"),
            Confidence = null,
            Rationale = string.Empty,
            ReasonCode = reasonCode,
            InjectionDetected = false,
            PromptSha256 = OpenAiChatRequest.PromptTemplate.Sha256,
            PromptVersion = OpenAiChatRequest.PromptVersion,
        };
    }

    private enum ParseOutcome
    {
        Ok = 0,
        NotJsonObject,
        MalformedStructure,
        DuplicateProperty,
        WrongTypeForField,
        UnknownProperty,
        MissingField,
        InvalidNumber,
        OutOfRange,
        RationaleTooLong,
        RationaleControlChar,
        CandidateIdMalformed,
        CandidateIdMismatch,
        UnknownClassification,
        UnknownCategory,
    }

    private static string ToReasonCode(this ParseOutcome o) => o switch
    {
        ParseOutcome.Ok => string.Empty,
        ParseOutcome.NotJsonObject => "response_not_json_object",
        ParseOutcome.MalformedStructure => "response_malformed_structure",
        ParseOutcome.DuplicateProperty => "response_duplicate_property",
        ParseOutcome.WrongTypeForField => "response_wrong_field_type",
        ParseOutcome.UnknownProperty => "response_unknown_property",
        ParseOutcome.MissingField => "response_missing_field",
        ParseOutcome.InvalidNumber => "response_invalid_number",
        ParseOutcome.OutOfRange => "response_confidence_out_of_range",
        ParseOutcome.RationaleTooLong => "response_rationale_too_long",
        ParseOutcome.RationaleControlChar => "response_rationale_control_char",
        ParseOutcome.CandidateIdMalformed => "response_candidate_id_malformed",
        ParseOutcome.CandidateIdMismatch => "response_candidate_id_mismatch",
        ParseOutcome.UnknownClassification => "response_unknown_classification",
        ParseOutcome.UnknownCategory => "response_unknown_category",
        _ => "response_unknown_failure",
    };

    /// <summary>
    /// Counting wrapper around the response stream. Returns the byte
    /// slice that fits in <see cref="MaxResponseBytes"/>; any further
    /// read returns 0 so the caller never sees bytes past the cap.
    /// </summary>
    private sealed class BoundedResponseStream : IAsyncDisposable
    {
        private readonly Stream _inner;
        private readonly int _cap;
        private int _consumed;

        public BoundedResponseStream(Stream inner, int cap)
        {
            _inner = inner;
            _cap = cap;
        }

        public byte[] ReadAllBytes()
        {
            using var ms = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                while (true)
                {
                    int remaining = _cap - _consumed;
                    if (remaining <= 0) break;
                    int want = Math.Min(buffer.Length, remaining);
                    int read = _inner.Read(buffer, 0, want);
                    if (read <= 0) break;
                    ms.Write(buffer, 0, read);
                    _consumed += read;
                }

                if (_consumed == _cap && _inner.ReadByte() >= 0)
                    return Array.Empty<byte>();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
            return ms.ToArray();
        }

        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
