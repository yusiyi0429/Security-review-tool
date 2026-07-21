using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;
using ReviewDifferenceStatus = SecurityReview.Domain.Reviews.DifferenceStatus;

namespace SecurityReview.Application.Diff;

/// <summary>
/// Computes stable differences between two scans of the same asset lineage.
/// Each finding occurrence is classified as New, Persistent, Resolved,
/// ReappearedAfterRuleChange, or UnreviewableThisRun.
///
/// The primary matching key combines asset lineage + path HMAC + canonical
/// locator kind/display + rule ID + value HMAC. Secondary matching (moved
/// or similar) may annotate but never changes the primary classification.
/// </summary>
public sealed class ScanDiffService
{
    private readonly IFindingRepository _findingRepository;
    private readonly ICoverageRepository _coverageRepository;

    public ScanDiffService(
        IFindingRepository findingRepository,
        ICoverageRepository coverageRepository)
    {
        _findingRepository = findingRepository;
        _coverageRepository = coverageRepository;
    }

    /// <summary>
    /// Computes the diff between current-scan findings and a previous scan
    /// within the same asset lineage. Returns one <see cref="FindingDiff"/>
    /// per current occurrence plus one <see cref="FindingDiff"/> per
    /// unmatched previous occurrence (for Resolved/UnreviewableThisRun).
    /// </summary>
    public async Task<IReadOnlyList<FindingDiff>> ComputeDiffAsync(
        ScanId currentScanId,
        ScanId? previousScanId,
        IReadOnlyList<FindingGroup> currentGroups,
        IReadOnlyList<FindingOccurrence> currentOccurrences,
        bool rulePackChanged,
        IReadOnlySet<string>? newlyEnabledRuleIds,
        CancellationToken cancellationToken = default)
    {
        var diffs = new List<FindingDiff>();

        // If no previous scan exists, all findings are New.
        if (previousScanId is null)
        {
            foreach (var occ in currentOccurrences)
                diffs.Add(new FindingDiff(occ.Id, ReviewDifferenceStatus.New, null));
            return diffs;
        }

        // Load previous scan findings.
        var previousGroups = await _findingRepository
            .GetGroupsByScanIdAsync(previousScanId.Value, cancellationToken)
            .ConfigureAwait(false);

        var previousOccurrences = new List<FindingOccurrence>();
        foreach (var group in previousGroups)
        {
            var occs = await _findingRepository
                .GetOccurrencesByGroupIdAsync(group.Id, cancellationToken)
                .ConfigureAwait(false);
            foreach (var occ in occs)
                previousOccurrences.Add(occ);
        }

        // Build a lookup table: previous occurrences indexed by matching key.
        var groupValueFingerprints = currentGroups
            .ToDictionary(g => g.Id, g => g.ValueFingerprint);
        var prevGroupValueFingerprints = previousGroups
            .ToDictionary(g => g.Id, g => g.ValueFingerprint);

        var previousByKey = new Dictionary<string, FindingOccurrence>();
        foreach (var prevOcc in previousOccurrences)
        {
            string key = BuildMatchingKey(
                prevOcc, prevGroupValueFingerprints.GetValueOrDefault(prevOcc.GroupId));
            previousByKey[key] = prevOcc;
        }

        // Match current occurrences against previous.
        var matchedPreviousKeys = new HashSet<string>();
        newlyEnabledRuleIds ??= new HashSet<string>();

        foreach (var currentOcc in currentOccurrences)
        {
            string key = BuildMatchingKey(
                currentOcc, groupValueFingerprints.GetValueOrDefault(currentOcc.GroupId));

            if (previousByKey.TryGetValue(key, out var matchingPrev))
            {
                matchedPreviousKeys.Add(key);

                // Check if this is a reappearance due to rule change.
                if (rulePackChanged && IsReappearedAfterRuleChange(
                    currentOcc, matchingPrev, newlyEnabledRuleIds))
                {
                    diffs.Add(new FindingDiff(currentOcc.Id,
                        ReviewDifferenceStatus.ReappearedAfterRuleChange,
                        matchingPrev.Id.Value.ToString()));
                }
                else
                {
                    diffs.Add(new FindingDiff(currentOcc.Id,
                        ReviewDifferenceStatus.Persistent,
                        matchingPrev.Id.Value.ToString()));
                }
            }
            else
            {
                diffs.Add(new FindingDiff(currentOcc.Id,
                    ReviewDifferenceStatus.New, null));
            }
        }

        // For unmatched previous occurrences, determine if Resolved or UnreviewableThisRun.
        var coverageGaps = await _coverageRepository
            .GetByScanIdAsync(currentScanId, cancellationToken)
            .ConfigureAwait(false);

        foreach (var kv in previousByKey)
        {
            if (matchedPreviousKeys.Contains(kv.Key)) continue;

            var prevOcc = kv.Value;
            bool isCovered = IsLocationCoveredThisRun(prevOcc.VirtualPath, coverageGaps);
            diffs.Add(new FindingDiff(
                prevOcc.Id,
                isCovered ? ReviewDifferenceStatus.Resolved : ReviewDifferenceStatus.UnreviewableThisRun,
                null));
        }

        return diffs;
    }

    /// <summary>
    /// Builds the primary matching key: asset lineage (file SHA-256 prefix) +
    /// path HMAC + canonical locator kind/display + rule ID + value HMAC.
    /// All components are lowercased hex SHA-256 hashes or domain identifiers
    /// — no raw values, paths, or secrets.
    /// </summary>
    private static string BuildMatchingKey(
        FindingOccurrence occurrence,
        ValueFingerprint? valueFingerprint)
    {
        string pathHmac = ComputeSha256LowerHex(occurrence.VirtualPath);
        string locatorDisplay = occurrence.CanonicalLocator.ToCanonicalDisplay();
        string filePrefix = occurrence.FileSha256.Length >= 16
            ? occurrence.FileSha256[..16]
            : occurrence.FileSha256;

        // Use the first provenance entry's RuleId; multi-provenance occurrences
        // already represent the same location/value across detectors.
        string ruleId = occurrence.Provenance.Count > 0
            ? occurrence.Provenance[0].RuleId.Value
            : "unknown-rule";

        string valueHmac = valueFingerprint?.HexString ?? string.Empty;

        string canonical = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"diff|{filePrefix}|{pathHmac}|{locatorDisplay}|{ruleId}|{valueHmac}");
        return ComputeSha256LowerHex(canonical);
    }

    /// <summary>
    /// Checks whether the finding is attributable to a rule repackaging
    /// where the same location and value now match a newly-enabled rule.
    /// </summary>
    private static bool IsReappearedAfterRuleChange(
        FindingOccurrence currentOcc,
        FindingOccurrence previousOcc,
        IReadOnlySet<string> newlyEnabledRuleIds)
    {
        // If any provenance entry has a newly-enabled rule and the previous
        // occurrence had a different rule at the same location/value, it's
        // a reappearance.
        foreach (var prov in currentOcc.Provenance)
        {
            if (newlyEnabledRuleIds.Contains(prov.RuleId.Value))
            {
                // Check that the previous occurrence didn't already have this rule.
                bool prevHasThisRule = previousOcc.Provenance
                    .Any(p => p.RuleId == prov.RuleId);
                if (!prevHasThisRule)
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Determines whether a file path is covered in the current scan by
    /// checking whether any coverage gap references it.
    /// </summary>
    private static bool IsLocationCoveredThisRun(
        string virtualPath,
        IReadOnlyList<CoverageGap> gaps)
    {
        foreach (var gap in gaps)
        {
            if (string.Equals(gap.VirtualPath, virtualPath, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static string ComputeSha256LowerHex(string input)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(hash);
    }
}

/// <summary>
/// The diff classification for a single finding occurrence between two
/// scans of the same asset lineage.
/// </summary>
public sealed record FindingDiff(
    FindingOccurrenceId OccurrenceId,
    ReviewDifferenceStatus Status,
    string? PreviousOccurrenceId);
