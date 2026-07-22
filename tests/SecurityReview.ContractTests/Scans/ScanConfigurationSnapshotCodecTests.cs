using System.Security.Cryptography;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Infrastructure.Cryptography;

namespace SecurityReview.ContractTests.Scans;

public sealed class ScanConfigurationSnapshotCodecTests : IDisposable
{
    private readonly AesGcmPayloadProtector _protector = new(
        RandomNumberGenerator.GetBytes(32), "test-key");

    public void Dispose() => _protector.Dispose();

    [Fact]
    public void Snapshot_round_trips_and_preserves_the_real_root()
    {
        ScanId scanId = new(Guid.NewGuid());
        ScanConfigurationSnapshot expected = BuildSnapshot("/synthetic/scan-root");
        var codec = new ScanConfigurationSnapshotCodec(_protector);

        byte[] encrypted = codec.Protect(scanId, expected);
        ScanConfigurationSnapshot actual = codec.Unprotect(
            BuildRecord(scanId, expected, encrypted));

        Assert.Equal(expected.ComputeHash(), actual.ComputeHash());
        Assert.Equal("/synthetic/scan-root", actual.RootPaths.Single());
    }

    [Fact]
    public void Snapshot_with_a_mismatched_record_hash_is_rejected()
    {
        ScanId scanId = new(Guid.NewGuid());
        ScanConfigurationSnapshot snapshot = BuildSnapshot("/synthetic/scan-root");
        var codec = new ScanConfigurationSnapshotCodec(_protector);
        byte[] encrypted = codec.Protect(scanId, snapshot);
        ScanSnapshotRecord record = BuildRecord(scanId, snapshot, encrypted) with
        {
            ConfigHash = new string('0', 64),
        };

        Assert.Throws<InvalidDataException>(() => codec.Unprotect(record));
    }

    private static ScanConfigurationSnapshot BuildSnapshot(string rootPath) => new(
        RootPaths: [rootPath],
        Manifest: new ManifestSnapshot(
            Manifest: null,
            OriginalSha256: null,
            Valid: true,
            Errors: Array.Empty<ManifestValidationError>()),
        UiOverrideComponentIds: [],
        ExclusionPatterns: [],
        ActiveRulePackHash: "rule-pack-hash",
        PolicySha256: new string('1', 64),
        LlmEndpointFingerprint: "endpoint",
        LlmModelFingerprint: "model",
        ClientVersion: "1.0.0",
        ParserAdapterVersion: "1.0.0",
        DetectorAdapterVersion: "1.0.0",
        PromptVersion: "1.0.0",
        Sandbox: new SandboxSelfTestResult(
            true,
            SandboxSelfTestResult.OkCode,
            new string('2', 64),
            "test-os",
            "test-profile",
            DateTimeOffset.UnixEpoch),
        EffectiveDetectorVersions: ["detector-v1"],
        CapturedAtUtc: DateTimeOffset.UnixEpoch);

    private static ScanSnapshotRecord BuildRecord(
        ScanId scanId,
        ScanConfigurationSnapshot snapshot,
        byte[] encrypted) => new(
            ScanId: scanId,
            CapturedAtUtc: snapshot.CapturedAtUtc,
            ConfigHash: snapshot.ComputeHash(),
            ActiveRulePackHash: snapshot.ActiveRulePackHash,
            PolicySha256: snapshot.PolicySha256,
            LlmEndpointFingerprint: snapshot.LlmEndpointFingerprint,
            LlmModelFingerprint: snapshot.LlmModelFingerprint,
            ClientVersion: snapshot.ClientVersion,
            ParserAdapterVersion: snapshot.ParserAdapterVersion,
            DetectorAdapterVersion: snapshot.DetectorAdapterVersion,
            PromptVersion: snapshot.PromptVersion,
            SandboxWorkerSha256: snapshot.Sandbox.WorkerSha256,
            EncryptedPayload: encrypted);
}
