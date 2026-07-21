using SecurityReview.Domain.Rules;

namespace SecurityReview.Domain.Findings;

/// <summary>
/// Records which detector and rule produced a finding at a specific location,
/// keeping both detection confidence and the semantic-review disposition
/// independently attributable. When two detectors/rule-pairs match the same
/// value at the same location, both provenance entries are preserved.
/// </summary>
public sealed record FindingProvenance(
    DetectorId DetectorId,
    RuleId RuleId,
    DetectionConfidence Confidence,
    bool RequiresSemanticReview);
