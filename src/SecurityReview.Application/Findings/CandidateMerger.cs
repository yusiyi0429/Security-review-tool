using System.Security.Cryptography;
using System.Text;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;

namespace SecurityReview.Application.Findings;

/// <summary>
/// Merges raw detection candidates into grouped findings with complete
/// provenance tracking. Same fingerprint → same group; same location+rule
/// from chunk overlap → single occurrence with merged provenance; different
/// detectors/rules at same location → both provenance entries preserved.
/// </summary>
public sealed class CandidateMerger
{
    private static readonly Guid DnsNamespace = new("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

    private readonly IValueFingerprintService _fingerprint;

    public CandidateMerger(IValueFingerprintService fingerprint)
    {
        _fingerprint = fingerprint;
    }

    public IReadOnlyList<FindingGroup> Merge(
        ScanId scanId,
        JobId jobId,
        IReadOnlyList<DetectionCandidate> candidates,
        string fileSha256,
        string virtualPath)
    {
        // Phase 1: Compute fingerprint for each candidate and group by it.
        // Within each fingerprint group, deduplicate by (canonicalLocator, ruleId).
        var groupsByFingerprint = new Dictionary<string, GroupBuilder>(StringComparer.Ordinal);

        foreach (var candidate in candidates)
        {
            var fp = _fingerprint.Compute(candidate.Value);
            if (!groupsByFingerprint.TryGetValue(fp.HexString, out var builder))
            {
                builder = new GroupBuilder(candidate.FindingKind, fp);
                groupsByFingerprint[fp.HexString] = builder;
            }

            string locatorKey = candidate.Locator.ToCanonicalDisplay();
            builder.AddCandidate(candidate, locatorKey, scanId, jobId, fileSha256, virtualPath);
        }

        // Phase 2: Build FindingGroup from each builder
        var result = new List<FindingGroup>(groupsByFingerprint.Count);
        foreach (var kvp in groupsByFingerprint)
        {
            result.Add(kvp.Value.Build(scanId, jobId, fileSha256, virtualPath));
        }

        return result;
    }

    private sealed class GroupBuilder
    {
        private readonly FindingKind _findingKind;
        private readonly ValueFingerprint _fingerprint;
        private Severity _maxSeverity = Severity.Info;
        private readonly Dictionary<string, OccurrenceBuilder> _occurrences = new(StringComparer.Ordinal);

        public GroupBuilder(FindingKind findingKind, ValueFingerprint fingerprint)
        {
            _findingKind = findingKind;
            _fingerprint = fingerprint;
        }

        public void AddCandidate(
            DetectionCandidate candidate,
            string locatorKey,
            ScanId scanId,
            JobId jobId,
            string fileSha256,
            string virtualPath)
        {
            if (IsMoreSevere(candidate.Severity, _maxSeverity))
                _maxSeverity = candidate.Severity;

            // Occurrence key: canonicalLocator only (different rules/detectors
            // at the same location merge into one occurrence with multiple provenance)
            string occurrenceKey = locatorKey;

            if (!_occurrences.TryGetValue(occurrenceKey, out var occBuilder))
            {
                occBuilder = new OccurrenceBuilder(
                    candidate.Value, candidate.Context, candidate.Locator,
                    scanId, jobId, fileSha256, virtualPath);
                _occurrences[occurrenceKey] = occBuilder;
            }

            occBuilder.AddProvenance(candidate);
        }

        /// <summary>
        /// Returns true when <paramref name="a"/> is more severe than <paramref name="b"/>.
        /// Severity ordinal: Critical (0) > High (1) > Medium (2) > Low (3) > Info (4).
        /// Lower integer value = higher severity.
        /// </summary>
        private static bool IsMoreSevere(Severity a, Severity b) => a < b;

        public FindingGroup Build(ScanId scanId, JobId jobId, string fileSha256, string virtualPath)
        {
            // Group key: scanId + category + valueHMAC
            string groupKey = $"{scanId.Value:N}|{_findingKind}|{_fingerprint.HexString}";
            var groupId = new FindingGroupId(MakeUuidV5(groupKey));

            var occurrences = new List<FindingOccurrence>(_occurrences.Count);
            foreach (var kvp in _occurrences)
            {
                occurrences.Add(kvp.Value.Build(groupId, scanId, jobId, fileSha256, virtualPath));
            }

            return new FindingGroup(groupId, _findingKind, _maxSeverity, _fingerprint, occurrences);
        }

        private sealed class OccurrenceBuilder
        {
            private readonly string _rawValue;
            private readonly string _rawContext;
            private readonly SourceLocator _canonicalLocator;
            private readonly ScanId _scanId;
            private readonly JobId _jobId;
            private readonly string _fileSha256;
            private readonly string _virtualPath;
            private readonly List<FindingProvenance> _provenance = [];

            public OccurrenceBuilder(
                string rawValue, string rawContext, SourceLocator locator,
                ScanId scanId, JobId jobId, string fileSha256, string virtualPath)
            {
                _rawValue = rawValue;
                _rawContext = rawContext;
                _canonicalLocator = locator;
                _scanId = scanId;
                _jobId = jobId;
                _fileSha256 = fileSha256;
                _virtualPath = virtualPath;
            }

            public void AddProvenance(DetectionCandidate candidate)
            {
                _provenance.Add(new FindingProvenance(
                    candidate.DetectorId, candidate.RuleId,
                    candidate.Confidence, candidate.RequiresSemanticReview));
            }

            public FindingOccurrence Build(
                FindingGroupId groupId, ScanId scanId, JobId jobId,
                string fileSha256, string virtualPath)
            {
                // Occurrence key: scanId + fileSha256 + virtualPath + canonicalLocator
                string occKey = $"{_scanId.Value:N}|{_fileSha256}|{_virtualPath}|{_canonicalLocator.ToCanonicalDisplay()}";
                var occId = new FindingOccurrenceId(MakeUuidV5(occKey));

                return new FindingOccurrence(
                    occId, groupId, _rawValue, _rawContext,
                    _canonicalLocator, _virtualPath, _fileSha256,
                    _provenance);
            }
        }
    }

    /// <summary>
    /// Generates a deterministic UUIDv5 for merging identification keys.
    /// Uses the DNS namespace UUID as the namespace seed. SHA-1 is only used
    /// for UUIDv5 spec compliance, not for any security-critical purpose.
    /// </summary>
#pragma warning disable CA5350 // SHA-1 is required by RFC 4122 for UUIDv5
    internal static FindingGroupId MakeGroupId(string groupKey) =>
        new(MakeUuidV5(groupKey));

    internal static FindingOccurrenceId MakeOccurrenceId(string occurrenceKey) =>
        new(MakeUuidV5(occurrenceKey));

    internal static Guid MakeUuidV5(string input)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(input);
        Span<byte> namespaceBytes = stackalloc byte[16];
        DnsNamespace.TryWriteBytes(namespaceBytes);

        // Compute SHA-1 of namespace + name
        Span<byte> combined = stackalloc byte[namespaceBytes.Length + nameBytes.Length];
        namespaceBytes.CopyTo(combined);
        nameBytes.CopyTo(combined[namespaceBytes.Length..]);

        byte[] hash = SHA1.HashData(combined);

        // Set version bits to 5 (0101xxxx)
        Span<byte> uuid = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(uuid);
        uuid[6] = (byte)((uuid[6] & 0x0F) | 0x50); // version 5
        uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80); // variant RFC 4122

        return new Guid(uuid);
    }
#pragma warning restore CA5350
}
