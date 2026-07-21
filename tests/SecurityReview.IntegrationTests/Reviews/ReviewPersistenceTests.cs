using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Domain;
using SecurityReview.Domain.Findings;
using ReviewDecisionStatus = SecurityReview.Domain.Reviews.ReviewStatus;
using SecurityReview.Domain.Reviews;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.Infrastructure.Persistence.Repositories;

namespace SecurityReview.IntegrationTests.Reviews;

public sealed class ReviewPersistenceTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public ReviewPersistenceTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-review-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        _hkdf = new HkdfSha256(masterKey);
        _protector = new AesGcmPayloadProtector(_hkdf.DeriveEncryptionKey(), "test-key");
        _fingerprint = new PersistentValueFingerprintService(_hkdf.DeriveFingerprintKey());

        using var init = new SqliteConnection($"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        new Migration001Initial().ApplyAsync(init, "test-integration", CancellationToken.None)
            .GetAwaiter().GetResult();
        init.Close();
    }

    public async ValueTask DisposeAsync()
    {
        _protector.Dispose();
        _fingerprint.Dispose();
        _hkdf.Dispose();

        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }

        await Task.CompletedTask;
    }

    private SqliteReviewRepository CreateReviewRepo() => new(_factory, _protector);
    private SqliteScanRepository CreateScanRepo() => new(_factory, _protector);
    private SqliteFindingRepository CreateFindingRepo() => new(_factory, _protector, _fingerprint);

    private async Task<(ScanId scanId, FindingOccurrenceId occurrenceId)> SetupOccurrenceAsync()
    {
        var scanId = new ScanId(Guid.NewGuid());
        var now = DateTimeOffset.UtcNow;
        var scan = new ScanRun(
            scanId, ScanStatus.Draft, now, now,
            "rule-fp", "client-v1", "pipeline-hash",
            PlannedCount: 1, Version: 1);
        await CreateScanRepo().InsertAsync(scan);

        var fileId = new FileId(Guid.NewGuid());

        // Insert file record directly via SQL since we only need the foreign key.
        await using var conn = await _factory.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO file_records (file_id, scan_id, path_hmac, coverage_status)
            VALUES (@fileId, @scanId, 'hmac-path', 0);
            """;
        cmd.Parameters.AddWithValue("@fileId", fileId.Value.ToString());
        cmd.Parameters.AddWithValue("@scanId", scanId.Value.ToString());
        await cmd.ExecuteNonQueryAsync();

        // Insert finding group and occurrence.
        var groupId = new FindingGroupId(Guid.NewGuid());
        var occurrenceId = new FindingOccurrenceId(Guid.NewGuid());
        var fingerprint = new ValueFingerprint("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

        var provenance = new FindingProvenance(
            new DetectorId("DET-001"),
            new RuleId("RULE-001"),
            DetectionConfidence.High,
            false);

        var occurrence = new FindingOccurrence(
            occurrenceId, groupId, "test-value", "test-context",
            new SourceLocator.TextLocator(1, 1, 0, 10),
            "/test/path.txt", "sha256-abc", [provenance]);

        var group = new FindingGroup(
            groupId, FindingKind.SensitiveContent, Severity.High,
            fingerprint, [occurrence]);

        await CreateFindingRepo().InsertGroupAsync(scanId, group);
        await CreateFindingRepo().InsertOccurrenceAsync(fileId, occurrence);

        return (scanId, occurrenceId);
    }

    // ---------- Decision round-trip ----------

    [Fact]
    public async Task Insert_and_read_decision_round_trip()
    {
        var (scanId, occurrenceId) = await SetupOccurrenceAsync();

        var decision = ReviewDecision.Create(
            scanId, null, occurrenceId,
            ReviewDecisionStatus.FalsePositive, "fp_review",
            new string('r', 50), "user-sid-hmac-001",
            DateTimeOffset.UtcNow);

        var repo = CreateReviewRepo();
        await repo.InsertDecisionAsync(decision);

        var readBack = await repo.GetDecisionsByOccurrenceAsync(occurrenceId);
        Assert.Single(readBack);
        Assert.Equal(decision.Id, readBack[0].Id);
        Assert.Equal(ReviewDecisionStatus.FalsePositive, readBack[0].Status);
        Assert.Equal("fp_review", readBack[0].ReasonCode);
        Assert.Equal(decision.EncryptedReason, readBack[0].EncryptedReason);
    }

    [Fact]
    public async Task GetDecisionById_returns_correct_decision()
    {
        var (scanId, occurrenceId) = await SetupOccurrenceAsync();

        var decision = ReviewDecision.Create(
            scanId, null, occurrenceId,
            ReviewDecisionStatus.ConfirmedRisk, "confirmed",
            new string('r', 100), "user-sid-hmac-002",
            DateTimeOffset.UtcNow);

        var repo = CreateReviewRepo();
        await repo.InsertDecisionAsync(decision);

        var readBack = await repo.GetDecisionByIdAsync(decision.Id);
        Assert.NotNull(readBack);
        Assert.Equal(decision.Id, readBack.Id);
        Assert.Equal(ReviewDecisionStatus.ConfirmedRisk, readBack.Status);
    }

    [Fact]
    public async Task Multiple_decisions_for_same_occurrence_are_append_only()
    {
        var (scanId, occurrenceId) = await SetupOccurrenceAsync();

        var decision1 = ReviewDecision.Create(
            scanId, null, occurrenceId,
            ReviewDecisionStatus.ConfirmedRisk, "first_pass",
            new string('a', 50), "user-sid-hmac-003",
            DateTimeOffset.UtcNow);

        // Small delay to ensure distinct timestamps.
        await Task.Delay(10);

        var decision2 = ReviewDecision.Create(
            scanId, null, occurrenceId,
            ReviewDecisionStatus.RemediatedAwaitingRescan, "fixed",
            new string('b', 50), "user-sid-hmac-003",
            DateTimeOffset.UtcNow);

        var repo = CreateReviewRepo();
        await repo.InsertDecisionAsync(decision1);
        await repo.InsertDecisionAsync(decision2);

        var decisions = await repo.GetDecisionsByOccurrenceAsync(occurrenceId);
        Assert.Equal(2, decisions.Count);

        // Latest decision should be first (descending order).
        Assert.Equal(decision2.Id, decisions[0].Id);
        Assert.Equal(decision1.Id, decisions[1].Id);

        // Both decisions still exist (not mutated/deleted).
        var d1 = await repo.GetDecisionByIdAsync(decision1.Id);
        var d2 = await repo.GetDecisionByIdAsync(decision2.Id);
        Assert.NotNull(d1);
        Assert.NotNull(d2);
    }

    // ---------- Exception grant round-trip ----------

    [Fact]
    public async Task Insert_and_read_grant_round_trip()
    {
        var (scanId, _) = await SetupOccurrenceAsync();

        var binding = ExceptionBinding.Create(
            "hmac-aid", "hmac-ver", "hmac-path", "hmac-loc",
            "hmac-val", "rule-hash-abc", "RULE-001");

        var future = DateTimeOffset.UtcNow.AddDays(30);
        var grant = ExceptionGrant.Create(
            binding, "rule-hash-abc", future,
            "user-sid-hmac-004", new string('g', 100));

        var repo = CreateReviewRepo();
        await repo.InsertExceptionGrantAsync(grant);

        var readBack = await repo.GetGrantByIdAsync(grant.Id);
        Assert.NotNull(readBack);
        Assert.Equal(grant.Id, readBack.Id);
        Assert.Equal(binding, readBack.Binding);
        Assert.Equal("rule-hash-abc", readBack.RulePackHash);
        Assert.Equal(grant.ValidUntilUtc, readBack.ValidUntilUtc);
        Assert.Equal(grant.EncryptedReason, readBack.EncryptedReason);
    }

    [Fact]
    public async Task GetActiveGrantsByBinding_returns_matching_non_expired_grants()
    {
        var (scanId, _) = await SetupOccurrenceAsync();

        var binding = ExceptionBinding.Create(
            "hmac-aid-2", "hmac-ver-2", "hmac-path-2", "hmac-loc-2",
            "hmac-val-2", "rule-hash-xyz", "RULE-002");

        var future = DateTimeOffset.UtcNow.AddDays(30);
        var grant = ExceptionGrant.Create(
            binding, "rule-hash-xyz", future,
            "user-sid-hmac-005", new string('g', 100));

        var repo = CreateReviewRepo();
        await repo.InsertExceptionGrantAsync(grant);

        string assetBinding = "hmac-aid-2|hmac-ver-2";
        string occurrenceBinding = "hmac-path-2|hmac-loc-2|hmac-val-2|RULE-002";

        var active = await repo.GetActiveGrantsByBindingAsync(assetBinding, occurrenceBinding);
        Assert.Single(active);
        Assert.Equal(grant.Id, active[0].Id);
    }

    [Fact]
    public async Task GetActiveGrantsByBinding_does_not_return_expired_grants()
    {
        var (scanId, _) = await SetupOccurrenceAsync();

        var binding = ExceptionBinding.Create(
            "hmac-aid-3", "hmac-ver-3", "hmac-path-3", "hmac-loc-3",
            "hmac-val-3", "rule-hash-zzz", "RULE-003");

        // Grant already expired.
        var past = DateTimeOffset.UtcNow.AddDays(-1);
        var grant = CreateExpiredGrant(binding, "rule-hash-zzz", past);

        var repo = CreateReviewRepo();
        await repo.InsertExceptionGrantAsync(grant);

        string assetBinding = "hmac-aid-3|hmac-ver-3";
        string occurrenceBinding = "hmac-path-3|hmac-loc-3|hmac-val-3|RULE-003";

        var active = await repo.GetActiveGrantsByBindingAsync(assetBinding, occurrenceBinding);
        Assert.Empty(active);
    }

    [Fact]
    public async Task GetActiveGrantsByBinding_requires_exact_match()
    {
        var (scanId, _) = await SetupOccurrenceAsync();

        var binding = ExceptionBinding.Create(
            "hmac-aid-4", "hmac-ver-4", "hmac-path-4", "hmac-loc-4",
            "hmac-val-4", "rule-hash-aaa", "RULE-004");

        var future = DateTimeOffset.UtcNow.AddDays(30);
        var grant = ExceptionGrant.Create(
            binding, "rule-hash-aaa", future,
            "user-sid-hmac-006", new string('g', 100));

        var repo = CreateReviewRepo();
        await repo.InsertExceptionGrantAsync(grant);

        // Asset matches but occurrence doesn't.
        string assetBinding = "hmac-aid-4|hmac-ver-4";
        string wrongOccurrence = "wrong-path|wrong-loc|wrong-val|RULE-004";

        var active = await repo.GetActiveGrantsByBindingAsync(assetBinding, wrongOccurrence);
        Assert.Empty(active);
    }

    [Fact]
    public async Task GetDecisionsByGroup_returns_decisions_for_group()
    {
        var (scanId, occurrenceId) = await SetupOccurrenceAsync();

        var groupId = new FindingGroupId(Guid.NewGuid());
        var decision = ReviewDecision.Create(
            scanId, groupId, null,
            ReviewDecisionStatus.ConfirmedRisk, "group_level",
            new string('g', 50), "user-sid-hmac-007",
            DateTimeOffset.UtcNow);

        var repo = CreateReviewRepo();
        await repo.InsertDecisionAsync(decision);

        var decisions = await repo.GetDecisionsByGroupAsync(groupId);
        Assert.Single(decisions);
        Assert.Equal(decision.Id, decisions[0].Id);
    }

    // ---------- Helpers ----------

    private static ExceptionGrant CreateExpiredGrant(
        ExceptionBinding binding, string rulePackHash, DateTimeOffset validUntilUtc)
    {
        // We bypass Create() validation for expired grants testing by using `with`.
        var grant = ExceptionGrant.Create(
            binding, rulePackHash,
            DateTimeOffset.UtcNow.AddDays(30), // temp future for Create()
            "user-sid-hmac-999", new string('e', 50));

        return grant with { ValidUntilUtc = validUntilUtc };
    }
}
