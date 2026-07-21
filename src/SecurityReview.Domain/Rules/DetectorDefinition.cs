using System.Text.Json.Serialization;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;

namespace SecurityReview.Domain.Rules;

public sealed record DetectorDefinition
{
    [JsonConverter(typeof(DetectorIdJsonConverter))]
    public DetectorId Id { get; init; }

    public DetectorKind Kind { get; init; }
    public string ConfigId { get; init; } = "";
    public Dictionary<string, string> Parameters { get; init; } =
        new Dictionary<string, string>();
    public int MaxMatchesPerChunk { get; init; } = 100;

    public static readonly int MaxParameters = 1_000;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (!IsValidDetectorId(Id.Value))
        {
            errors.Add($"Invalid DetectorId format: '{Id.Value}'. Must match DET-[A-Z0-9-]{{3,64}}.");
        }

        if (string.IsNullOrWhiteSpace(ConfigId))
        {
            errors.Add("ConfigId must not be empty.");
        }

        if (Parameters.Count > MaxParameters)
        {
            errors.Add($"Detector has {Parameters.Count} parameters; max is {MaxParameters}.");
        }

        if (MaxMatchesPerChunk < 1)
        {
            errors.Add("MaxMatchesPerChunk must be at least 1.");
        }

        return errors;
    }

    public static bool IsValidDetectorId(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        if (!value.StartsWith("DET-", StringComparison.Ordinal)) return false;

        string suffix = value.AsSpan(4).ToString();
        if (suffix.Length < 3 || suffix.Length > 64) return false;

        foreach (char c in suffix)
        {
            if (!(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-'))
                return false;
        }

        return true;
    }
}
