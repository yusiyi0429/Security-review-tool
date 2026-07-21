using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Command to create a new scan run. Carries every input that the
/// preflight snapshot must capture and validate. The orchestrator and
/// every later stage only ever sees the snapshot — the original UI
/// state is discarded after the snapshot hash is computed.
/// </summary>
public sealed record CreateScanCommand(
    string[] RootPaths,
    ManifestSnapshot Manifest,
    string[] UiOverrideComponentIds,
    string[] ExclusionPatterns,
    string ActiveRulePackHash,
    string PolicySha256,
    string LlmEndpointFingerprint,
    string LlmModelFingerprint,
    string ClientVersion,
    string ParserAdapterVersion,
    string DetectorAdapterVersion,
    string PromptVersion,
    SandboxSelfTestResult Sandbox,
    string[] EffectiveDetectorVersions)
{
    public const int MaxRoots = 64;
    public const int MaxExclusions = 256;

    public void Validate()
    {
        if (RootPaths is null || RootPaths.Length == 0)
        {
            throw new InvalidScanInputException("At least one root path is required.");
        }

        if (RootPaths.Length > MaxRoots)
        {
            throw new InvalidScanInputException(
                $"Too many root paths ({RootPaths.Length}); max {MaxRoots}.");
        }

        foreach (string root in RootPaths)
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new InvalidScanInputException("Root path entries must be non-empty.");
            }
        }

        if (ExclusionPatterns.Length > MaxExclusions)
        {
            throw new InvalidScanInputException(
                $"Too many exclusion patterns ({ExclusionPatterns.Length}); max {MaxExclusions}.");
        }

        if (string.IsNullOrEmpty(ActiveRulePackHash))
        {
            throw new InvalidScanInputException("Active rule pack hash is required.");
        }

        if (string.IsNullOrEmpty(PolicySha256))
        {
            throw new InvalidScanInputException("Effective policy SHA-256 is required.");
        }

        if (string.IsNullOrEmpty(ClientVersion))
        {
            throw new InvalidScanInputException("Client version is required.");
        }

        if (Sandbox is null || !Sandbox.Passed)
        {
            throw new InvalidScanInputException(
                "Sandbox self-test result must be a passing record.");
        }
    }
}

/// <summary>
/// Thrown when a <see cref="CreateScanCommand"/> cannot be accepted.
/// Mapped by handlers to the user-facing preflight error code.
/// </summary>
public sealed class InvalidScanInputException : Exception
{
    public InvalidScanInputException(string message) : base(message) { }
}
