using SecurityReview.Domain.Llm;

namespace SecurityReview.Application.Llm;

/// <summary>
/// Command to verify the LLM endpoint is reachable, that the configured
/// authentication succeeds, and that the connection is restricted to the
/// approved origin. The service performs a fixed, synthetic request:
/// the body is the literal <c>SYNTHETIC_CONNECTION_TEST</c> string and
/// the response format is the fixed connection-test schema. The
/// command never queries scan repositories.
/// </summary>
public sealed record TestLlmConnectionCommand(
    LlmEndpointOptions Options,
    string? CorrelationId = null);
