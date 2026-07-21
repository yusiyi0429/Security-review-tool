using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;

namespace SecurityReview.RulePackBuilder.Schema;

public sealed record WorkbookCategory
{
    public string CategoryId { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(CategoryId))
        {
            errors.Add("CategoryId must not be empty.");
        }
        else if (!IsValidCategoryId(CategoryId))
        {
            errors.Add("Invalid CategoryId format; expected SENS-001..SENS-008.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("Category Name must not be empty.");
        }

        return errors;
    }

    public CategoryDefinition ToDomain()
    {
        return new CategoryDefinition
        {
            CategoryId = Domain.Assets.CategoryId.Parse(CategoryId),
            Name = Name,
            Description = Description,
            Enabled = Enabled,
        };
    }

    private static bool IsValidCategoryId(string value)
    {
        return value.Length == 8
            && value.StartsWith("SENS-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(5), out var n)
            && n >= 1 && n <= 8;
    }
}

public sealed record WorkbookAsset
{
    public string AssetTypeId { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string FocusWeights { get; init; } = "";

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(AssetTypeId))
        {
            errors.Add("AssetTypeId must not be empty.");
        }
        else if (!IsValidAssetTypeId(AssetTypeId))
        {
            errors.Add("Invalid AssetTypeId format; expected ASSET-001..ASSET-011.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("Asset Name must not be empty.");
        }

        if (!string.IsNullOrWhiteSpace(FocusWeights))
        {
            errors.AddRange(ValidateFocusWeightsJson(FocusWeights));
        }

        return errors;
    }

    public AssetPolicy ToDomain()
    {
        var weights = new Dictionary<Domain.Assets.CategoryId, double>();
        if (!string.IsNullOrWhiteSpace(FocusWeights))
        {
            using var doc = JsonDocument.Parse(FocusWeights);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                weights[Domain.Assets.CategoryId.Parse(prop.Name)] = prop.Value.GetDouble();
            }
        }

        return new AssetPolicy
        {
            AssetTypeId = Domain.Assets.AssetTypeId.Parse(AssetTypeId),
            Name = Name,
            Description = Description,
            FocusWeights = weights,
        };
    }

    private static List<string> ValidateFocusWeightsJson(string json)
    {
        var errors = new List<string>();

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            errors.Add("FocusWeights is not valid JSON.");
            return errors;
        }

        using (doc)
        {
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (!IsValidCategoryId(prop.Name))
                {
                    errors.Add("FocusWeights contains an invalid CategoryId key; expected SENS-001..SENS-008.");
                    break;
                }

                if (!prop.Value.TryGetDouble(out var d) || double.IsNaN(d) || double.IsInfinity(d) || d < 0)
                {
                    errors.Add("FocusWeights contains an invalid weight value; expected a non-negative number.");
                    break;
                }
            }
        }

        return errors;
    }

    private static bool IsValidCategoryId(string value)
    {
        return value.Length == 8
            && value.StartsWith("SENS-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(5), out var n)
            && n >= 1 && n <= 8;
    }

    private static bool IsValidAssetTypeId(string value)
    {
        return value.Length == 9
            && value.StartsWith("ASSET-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(6), out var n)
            && n >= 1 && n <= 11;
    }
}

public sealed record WorkbookComplianceRule
{
    public string Id { get; init; } = "";
    public string AssetTypeId { get; init; } = "";
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string EvidenceField { get; init; } = "";
    public string RequiredStatus { get; init; } = "";

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Id))
        {
            errors.Add("ComplianceRule Id must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(AssetTypeId))
        {
            errors.Add("ComplianceRule AssetTypeId must not be empty.");
        }
        else if (!IsValidAssetTypeId(AssetTypeId))
        {
            errors.Add("Invalid ComplianceRule AssetTypeId format; expected ASSET-001..ASSET-011.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("ComplianceRule Name must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(EvidenceField))
        {
            errors.Add("ComplianceRule EvidenceField must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(RequiredStatus))
        {
            errors.Add("ComplianceRule RequiredStatus must not be empty.");
        }

        return errors;
    }

    public ComplianceRule ToDomain()
    {
        return new ComplianceRule
        {
            Id = Id,
            AssetTypeId = Domain.Assets.AssetTypeId.Parse(AssetTypeId),
            Name = Name,
            Description = Description,
            EvidenceField = EvidenceField,
            RequiredStatus = RequiredStatus,
        };
    }

    private static bool IsValidAssetTypeId(string value)
    {
        return value.Length == 9
            && value.StartsWith("ASSET-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(6), out var n)
            && n >= 1 && n <= 11;
    }
}

public sealed record WorkbookRule
{
    public string RuleId { get; init; } = "";
    public string CategoryId { get; init; } = "";
    public string FindingKind { get; init; } = "";
    public string Severity { get; init; } = "";
    public string DetectionConfidence { get; init; } = "";
    public string DetectorId { get; init; } = "";
    public string DetectorConfigId { get; init; } = "";
    public string AppliesToAssets { get; init; } = "";
    public bool RequiresSemanticReview { get; init; }
    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(RuleId))
        {
            errors.Add("RuleId must not be empty.");
        }
        else if (!RuleDefinition.IsValidRuleId(RuleId))
        {
            errors.Add("Invalid RuleId format; expected RULE-[A-Z0-9-]{3,64}.");
        }

        if (string.IsNullOrWhiteSpace(CategoryId))
        {
            errors.Add("Rule CategoryId must not be empty.");
        }
        else if (!IsValidCategoryId(CategoryId))
        {
            errors.Add("Invalid Rule CategoryId format; expected SENS-001..SENS-008.");
        }

        if (string.IsNullOrWhiteSpace(FindingKind) || !Enum.TryParse<Domain.Findings.FindingKind>(FindingKind, ignoreCase: false, out _))
        {
            errors.Add("Invalid FindingKind; expected SensitiveContent or AssetCompliance.");
        }

        if (string.IsNullOrWhiteSpace(Severity) || !Enum.TryParse<Domain.Findings.Severity>(Severity, ignoreCase: false, out _))
        {
            errors.Add("Invalid Severity; expected Critical, High, Medium, Low, or Info.");
        }

        if (string.IsNullOrWhiteSpace(DetectionConfidence) || !Enum.TryParse<Domain.Findings.DetectionConfidence>(DetectionConfidence, ignoreCase: false, out _))
        {
            errors.Add("Invalid DetectionConfidence; expected High, Medium, or Low.");
        }

        if (string.IsNullOrWhiteSpace(DetectorId))
        {
            errors.Add("Rule DetectorId must not be empty.");
        }
        else if (!DetectorDefinition.IsValidDetectorId(DetectorId))
        {
            errors.Add("Invalid Rule DetectorId format; expected DET-[A-Z0-9-]{3,64}.");
        }

        if (string.IsNullOrWhiteSpace(DetectorConfigId))
        {
            errors.Add("Rule DetectorConfigId must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(AppliesToAssets))
        {
            errors.Add("Rule AppliesToAssets must not be empty.");
        }
        else
        {
            errors.AddRange(ValidateAppliesToAssets(AppliesToAssets));
        }

        return errors;
    }

    public RuleDefinition ToDomain()
    {
        var assets = new HashSet<Domain.Assets.AssetTypeId>();
        foreach (var token in AppliesToAssets.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            assets.Add(Domain.Assets.AssetTypeId.Parse(token));
        }

        return new RuleDefinition
        {
            Id = new SecurityReview.Domain.RuleId(RuleId),
            CategoryId = Domain.Assets.CategoryId.Parse(CategoryId),
            FindingKind = Enum.Parse<Domain.Findings.FindingKind>(FindingKind),
            Severity = Enum.Parse<Domain.Findings.Severity>(Severity),
            Confidence = Enum.Parse<Domain.Findings.DetectionConfidence>(DetectionConfidence),
            DetectorId = new SecurityReview.Domain.DetectorId(DetectorId),
            DetectorConfigId = DetectorConfigId,
            AppliesToAssets = assets,
            RequiresSemanticReview = RequiresSemanticReview,
            Enabled = Enabled,
        };
    }

    private static List<string> ValidateAppliesToAssets(string value)
    {
        var errors = new List<string>();
        var tokens = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (tokens.Length == 0)
        {
            errors.Add("Rule AppliesToAssets must not be empty.");
            return errors;
        }

        foreach (var token in tokens)
        {
            if (!IsValidAssetTypeId(token))
            {
                errors.Add("Rule AppliesToAssets contains an invalid asset type; expected ASSET-001..ASSET-011.");
                break;
            }
        }

        return errors;
    }

    private static bool IsValidCategoryId(string value)
    {
        return value.Length == 8
            && value.StartsWith("SENS-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(5), out var n)
            && n >= 1 && n <= 8;
    }

    private static bool IsValidAssetTypeId(string value)
    {
        return value.Length == 9
            && value.StartsWith("ASSET-", StringComparison.Ordinal)
            && int.TryParse(value.AsSpan(6), out var n)
            && n >= 1 && n <= 11;
    }
}

public sealed record WorkbookDetector
{
    public string DetectorId { get; init; } = "";
    public string Kind { get; init; } = "";
    public string ConfigId { get; init; } = "";
    public string Parameters { get; init; } = "";
    public int MaxMatchesPerChunk { get; init; } = 100;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(DetectorId))
        {
            errors.Add("DetectorId must not be empty.");
        }
        else if (!DetectorDefinition.IsValidDetectorId(DetectorId))
        {
            errors.Add("Invalid DetectorId format; expected DET-[A-Z0-9-]{3,64}.");
        }

        if (string.IsNullOrWhiteSpace(Kind) || !Enum.TryParse<Domain.Rules.DetectorKind>(Kind, ignoreCase: false, out _))
        {
            errors.Add("Invalid Detector Kind; expected KnownFormat, Checksum, StructuredField, NetworkAddress, Dictionary, EntropyWithContext, LicenseFingerprint, ContentFingerprint, or SemanticCandidate.");
        }

        if (string.IsNullOrWhiteSpace(ConfigId))
        {
            errors.Add("Detector ConfigId must not be empty.");
        }

        if (!string.IsNullOrWhiteSpace(Parameters))
        {
            errors.AddRange(ValidateParametersJson(Parameters));
        }

        if (MaxMatchesPerChunk < 1)
        {
            errors.Add("Detector MaxMatchesPerChunk must be at least 1.");
        }

        return errors;
    }

    public DetectorDefinition ToDomain()
    {
        var parameters = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(Parameters))
        {
            using var doc = JsonDocument.Parse(Parameters);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                parameters[prop.Name] = prop.Value.GetString() ?? "";
            }
        }

        return new DetectorDefinition
        {
            Id = new SecurityReview.Domain.DetectorId(DetectorId),
            Kind = Enum.Parse<Domain.Rules.DetectorKind>(Kind),
            ConfigId = ConfigId,
            Parameters = parameters,
            MaxMatchesPerChunk = MaxMatchesPerChunk,
        };
    }

    private static List<string> ValidateParametersJson(string json)
    {
        var errors = new List<string>();

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            errors.Add("Detector Parameters is not valid JSON.");
            return errors;
        }

        using (doc)
        {
            var count = 0;
            foreach (var _ in doc.RootElement.EnumerateObject())
            {
                count++;
            }

            if (count > DetectorDefinition.MaxParameters)
            {
                errors.Add($"Detector Parameters exceeds the maximum of {DetectorDefinition.MaxParameters}.");
            }
        }

        return errors;
    }
}
