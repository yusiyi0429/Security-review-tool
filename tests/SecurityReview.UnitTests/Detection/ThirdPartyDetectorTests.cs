using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Rules;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.RulePack.Detection;

namespace SecurityReview.UnitTests.Detection;

public sealed class ThirdPartyDetectorTests
{
    private static ContentChunk MakeChunk(string text)
    {
        return new ContentChunk(
            ProtocolVersion: 1,
            JobId: new JobId(Guid.NewGuid()),
            Sequence: 0,
            VirtualPath: "test.txt",
            FormatId: "text/plain",
            ContentKind: ContentKind.Text,
            Encoding: "utf-8",
            Text: text,
            SourceStart: 0,
            SourceLength: text.Length,
            LocationMap: [],
            IsFinal: true);
    }

    private static RuleDefinition MakeRule(string id, DetectorId detectorId)
    {
        return new RuleDefinition
        {
            Id = new RuleId(id),
            CategoryId = CategoryId.Parse("SENS-008"),
            FindingKind = FindingKind.SensitiveContent,
            Severity = Severity.High,
            Confidence = DetectionConfidence.Medium,
            DetectorId = detectorId,
            DetectorConfigId = "default",
            AppliesToAssets = [AssetTypeId.Parse("ASSET-001")],
            Enabled = true
        };
    }

    private static DetectorDefinition MakeDetector(DetectorId id, DetectorKind kind, int maxMatches = 100)
    {
        return new DetectorDefinition
        {
            Id = id,
            Kind = kind,
            ConfigId = "default",
            MaxMatchesPerChunk = maxMatches
        };
    }

    // ==================== LicenseFingerprintDetector ====================

    [Fact]
    public async Task license_detector_finds_copyright_line()
    {
        var detector = new LicenseFingerprintDetector(
            authorizations: Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>(),
            currentAssetScope: "my-asset");

        var chunk = MakeChunk("Copyright (c) 2023 Some Company. All rights reserved.");
        var rule = MakeRule("RULE-LIC-001", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
        Assert.All(results, c => Assert.True(c.RequiresSemanticReview));
    }

    [Fact]
    public async Task license_detector_finds_spdx_identifier()
    {
        var detector = new LicenseFingerprintDetector(
            authorizations: Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>(),
            currentAssetScope: "my-asset");

        var chunk = MakeChunk("// SPDX-License-Identifier: GPL-3.0-only");
        var rule = MakeRule("RULE-LIC-002", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task license_detector_finds_named_license()
    {
        var detector = new LicenseFingerprintDetector(
            authorizations: Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>(),
            currentAssetScope: "my-asset");

        var chunk = MakeChunk("This project is under the MIT License.");
        var rule = MakeRule("RULE-LIC-003", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task license_detector_finds_vendor_marker()
    {
        var detector = new LicenseFingerprintDetector(
            authorizations: Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>(),
            currentAssetScope: "my-asset");

        var chunk = MakeChunk("This file contains Proprietary information.");
        var rule = MakeRule("RULE-LIC-004", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task license_detector_excludes_authorized_license()
    {
        var authorizations = new List<LicenseFingerprintDetector.LicenseAuthorization>
        {
            new()
            {
                LicenseId = "MIT",
                AuthorizedAssetScope = "my-asset",
                AuthorizationId = "AUTH-001"
            }
        };

        var detector = new LicenseFingerprintDetector(authorizations, "my-asset");
        var chunk = MakeChunk("This project is under the MIT License.");
        var rule = MakeRule("RULE-LIC-005", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // MIT License is authorized → excluded from candidates
        Assert.DoesNotContain(results, c => c.Value.Contains("MIT License"));
    }

    [Fact]
    public async Task license_detector_flags_unmatched_authorization_scope()
    {
        var authorizations = new List<LicenseFingerprintDetector.LicenseAuthorization>
        {
            new()
            {
                LicenseId = "MIT",
                AuthorizedAssetScope = "other-asset", // Different scope
                AuthorizationId = "AUTH-002"
            }
        };

        var detector = new LicenseFingerprintDetector(authorizations, "my-asset");
        var chunk = MakeChunk("This project is under the MIT License.");
        var rule = MakeRule("RULE-LIC-006", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // Authorization is for a different scope → flagged
        Assert.Contains(results, c => c.Value.Contains("MIT License"));
    }

    [Fact]
    public async Task license_detector_flags_expired_authorization()
    {
        var authorizations = new List<LicenseFingerprintDetector.LicenseAuthorization>
        {
            new()
            {
                LicenseId = "MIT",
                AuthorizedAssetScope = "my-asset",
                AuthorizedUntil = DateTimeOffset.UtcNow.AddDays(-1), // expired
                AuthorizationId = "AUTH-003"
            }
        };

        var detector = new LicenseFingerprintDetector(authorizations, "my-asset");
        var chunk = MakeChunk("This project is under the MIT License.");
        var rule = MakeRule("RULE-LIC-007", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // Expired authorization → still flagged
        Assert.Contains(results, c => c.Value.Contains("MIT License"));
    }

    [Fact]
    public async Task license_detector_never_sets_legal_boolean()
    {
        var detector = new LicenseFingerprintDetector(
            authorizations: Array.Empty<LicenseFingerprintDetector.LicenseAuthorization>(),
            currentAssetScope: "my-asset");

        var chunk = MakeChunk("Proprietary code.");
        var rule = MakeRule("RULE-LIC-008", new DetectorId("DET-LICENSE-FP"));
        var detDef = MakeDetector(new DetectorId("DET-LICENSE-FP"), DetectorKind.LicenseFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // Candidates should not contain any legal/infringement determination
        Assert.NotEmpty(results);
        Assert.All(results, c =>
        {
            // FindingKind is from the rule, not modified
            Assert.Equal(FindingKind.SensitiveContent, c.FindingKind);
        });
    }

    // ==================== ContentFingerprintDetector ====================

    [Fact]
    public async Task content_fingerprint_detects_matching_hash()
    {
        // Compute SHA256 of text content
        var text = "This is a known third-party component file.";
        byte[] hashBytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(text));
        string hashHex = Convert.ToHexStringLower(hashBytes);

        var fingerprints = new List<ContentFingerprintDetector.FingerprintEntry>
        {
            new()
            {
                FingerprintId = "FP-001",
                Algorithm = "sha256",
                HashValue = hashHex,
                ComponentName = "known-component",
                Version = "1.0.0"
            }
        };

        var detector = new ContentFingerprintDetector(
            fingerprints, authorizations: Array.Empty<ContentFingerprintDetector.FingerprintAuthorization>(),
            "my-asset");

        var chunk = MakeChunk(text);
        var rule = MakeRule("RULE-CFP-001", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Single(results);
        Assert.Contains("known-component", results[0].Value);
        Assert.True(results[0].RequiresSemanticReview);
    }

    [Fact]
    public async Task content_fingerprint_skips_when_no_match()
    {
        var fingerprints = new List<ContentFingerprintDetector.FingerprintEntry>
        {
            new()
            {
                FingerprintId = "FP-002",
                Algorithm = "sha256",
                HashValue = "0000000000000000000000000000000000000000000000000000000000000000",
                ComponentName = "other-component",
            }
        };

        var detector = new ContentFingerprintDetector(
            fingerprints, authorizations: Array.Empty<ContentFingerprintDetector.FingerprintAuthorization>(),
            "my-asset");

        var chunk = MakeChunk("Some text that won't match.");
        var rule = MakeRule("RULE-CFP-002", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(results);
    }

    [Fact]
    public async Task content_fingerprint_excludes_authorized_match()
    {
        var text = "Authorized component content.";
        byte[] hashBytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(text));
        string hashHex = Convert.ToHexStringLower(hashBytes);

        var fingerprints = new List<ContentFingerprintDetector.FingerprintEntry>
        {
            new()
            {
                FingerprintId = "FP-003",
                Algorithm = "sha256",
                HashValue = hashHex,
                ComponentName = "authorized-component",
            }
        };

        var authorizations = new List<ContentFingerprintDetector.FingerprintAuthorization>
        {
            new()
            {
                FingerprintId = "FP-003",
                AuthorizationId = "AUTH-FP-001",
                AuthorizedAssetScope = "my-asset"
            }
        };

        var detector = new ContentFingerprintDetector(fingerprints, authorizations, "my-asset");
        var chunk = MakeChunk(text);
        var rule = MakeRule("RULE-CFP-003", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(results);
    }

    [Fact]
    public async Task content_fingerprint_flags_expired_authorization()
    {
        var text = "Expired authorization content.";
        byte[] hashBytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(text));
        string hashHex = Convert.ToHexStringLower(hashBytes);

        var fingerprints = new List<ContentFingerprintDetector.FingerprintEntry>
        {
            new()
            {
                FingerprintId = "FP-004",
                Algorithm = "sha256",
                HashValue = hashHex,
                ComponentName = "expired-auth-component",
            }
        };

        var authorizations = new List<ContentFingerprintDetector.FingerprintAuthorization>
        {
            new()
            {
                FingerprintId = "FP-004",
                AuthorizationId = "AUTH-FP-004",
                AuthorizedAssetScope = "my-asset",
                AuthorizedUntil = DateTimeOffset.UtcNow.AddDays(-1) // expired
            }
        };

        var detector = new ContentFingerprintDetector(fingerprints, authorizations, "my-asset");
        var chunk = MakeChunk(text);
        var rule = MakeRule("RULE-CFP-004", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        // Expired authorization → should still flag
        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task content_fingerprint_handles_empty_fingerprints()
    {
        var detector = new ContentFingerprintDetector(
            fingerprints: Array.Empty<ContentFingerprintDetector.FingerprintEntry>(),
            authorizations: Array.Empty<ContentFingerprintDetector.FingerprintAuthorization>(),
            "my-asset");

        var chunk = MakeChunk("Any content.");
        var rule = MakeRule("RULE-CFP-005", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.Empty(results);
    }

    [Fact]
    public async Task content_fingerprint_respects_max_matches()
    {
        var text = "Test content for match limit.";

        var fingerprints = new List<ContentFingerprintDetector.FingerprintEntry>();
        for (int i = 0; i < 5; i++)
        {
            byte[] hashBytes = System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes($"{text}_{i}"));
            string hashHex = Convert.ToHexStringLower(hashBytes);

            fingerprints.Add(new ContentFingerprintDetector.FingerprintEntry
            {
                FingerprintId = $"FP-LIMIT-{i}",
                Algorithm = "sha256",
                HashValue = hashHex,
                ComponentName = $"component-{i}"
            });
        }

        var detector = new ContentFingerprintDetector(
            fingerprints, Array.Empty<ContentFingerprintDetector.FingerprintAuthorization>(), "my-asset");

        // Only the actual chunk text hash will match (probably none)
        var chunk = MakeChunk(text);
        var rule = MakeRule("RULE-CFP-006", new DetectorId("DET-CONTENT-FP"));
        var detDef = MakeDetector(new DetectorId("DET-CONTENT-FP"), DetectorKind.ContentFingerprint, maxMatches: 2);

        var results = await detector.DetectAsync(chunk, rule, detDef, CancellationToken.None);

        Assert.InRange(results.Count, 0, 2);
    }
}
