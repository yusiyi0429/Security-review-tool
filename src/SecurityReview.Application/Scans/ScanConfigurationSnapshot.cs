using SecurityReview.Application.Scans.Preflight;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Immutable fingerprint of every input that determines a scan's behaviour.
/// Captured at <see cref="CreateScanHandler"/> time and persisted alongside
/// the scan run so concurrent UI edits after Start cannot retroactively
/// change what the scan decided.
///
/// User edits made after <see cref="StartScanHandler"/> only affect future
/// scans — the snapshot's hash is what the diff service and audit trail
/// trust.
/// </summary>
public sealed record ScanConfigurationSnapshot(
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
    string[] EffectiveDetectorVersions,
    DateTimeOffset CapturedAtUtc,
    ManifestSnapshot[]? RootManifests = null,
    ScanExclusion[]? Exclusions = null)
{
    /// <summary>
    /// Returns a stable SHA-256 of the snapshot content. The hash covers
    /// every field except <see cref="CapturedAtUtc"/> so the same input
    /// set always produces the same hash — diff services and audit
    /// audits rely on this property.
    /// </summary>
    public string ComputeHash()
    {
        var canonical = new System.Text.StringBuilder(capacity: 512);
        canonical.Append("scan-config|");
        canonical.Append(string.Join("|", RootPaths.OrderBy(p => p, StringComparer.Ordinal)));
        canonical.Append('|');
        canonical.Append(Manifest.OriginalSha256 ?? string.Empty);
        canonical.Append('|');
        if (RootManifests is not null)
        {
            canonical.Append(string.Join(",",
                RootPaths.Select((path, index) =>
                    $"{index}:{path}:{RootManifests[index].OriginalSha256 ?? string.Empty}")));
        }
        canonical.Append('|');
        canonical.Append(string.Join(",",
            UiOverrideComponentIds.OrderBy(id => id, StringComparer.Ordinal)));
        canonical.Append('|');
        canonical.Append(string.Join(",",
            ExclusionPatterns.OrderBy(p => p, StringComparer.Ordinal)));
        canonical.Append('|');
        if (Exclusions is not null)
        {
            canonical.Append(string.Join(",",
                Exclusions
                    .OrderBy(exclusion => exclusion.Pattern, StringComparer.Ordinal)
                    .ThenBy(exclusion => exclusion.Reason, StringComparer.Ordinal)
                    .Select(exclusion =>
                        $"{exclusion.Pattern}:{exclusion.Reason}")));
        }
        canonical.Append('|');
        canonical.Append(ActiveRulePackHash);
        canonical.Append('|');
        canonical.Append(PolicySha256);
        canonical.Append('|');
        canonical.Append(LlmEndpointFingerprint);
        canonical.Append('|');
        canonical.Append(LlmModelFingerprint);
        canonical.Append('|');
        canonical.Append(ClientVersion);
        canonical.Append('|');
        canonical.Append(ParserAdapterVersion);
        canonical.Append('|');
        canonical.Append(DetectorAdapterVersion);
        canonical.Append('|');
        canonical.Append(PromptVersion);
        canonical.Append('|');
        canonical.Append(Sandbox.WorkerSha256);
        canonical.Append('|');
        canonical.Append(Sandbox.OsBuild);
        canonical.Append('|');
        canonical.Append(Sandbox.ProfileSid);
        canonical.Append('|');
        canonical.Append(string.Join(",",
            EffectiveDetectorVersions.OrderBy(v => v, StringComparer.Ordinal)));

        byte[] hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToHexStringLower(hash);
    }
}
