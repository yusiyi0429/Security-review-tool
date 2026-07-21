namespace SecurityReview.Domain.Llm;

/// <summary>
/// How the LLM client requests structured responses. The choice affects
/// only the wire shape; the <c>JsonSchema</c> default produces a fixed
/// schema that the connection-test service relies on.
/// </summary>
public enum LlmResponseFormatMode
{
    /// <summary>
    /// Send a JSON schema (<c>response_format: json_schema</c>) — the
    /// default. The connection test asserts this fixed schema.
    /// </summary>
    JsonSchema = 0,

    /// <summary>
    /// Ask for free-form JSON object (<c>response_format: json_object</c>).
    /// </summary>
    JsonObject = 1,

    /// <summary>
    /// Do not set <c>response_format</c> at all and rely on prompt
    /// instructions only. Useful for endpoints that reject either
    /// <c>json_schema</c> or <c>json_object</c>.
    /// </summary>
    PromptOnly = 2,
}