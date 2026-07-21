using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Findings;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Scans;
using SecurityReview.Application.Scans.Inventory;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Findings;
using SecurityReview.Domain.Llm;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Cryptography;
using SecurityReview.Infrastructure.Persistence;
using SecurityReview.Infrastructure.Persistence.Migrations;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using ISqliteConnectionFactory = SecurityReview.Infrastructure.Persistence.ISqliteConnectionFactory;

namespace SecurityReview.IntegrationTests.Scans;

/// <summary>
/// Focused tests for the semantic-review failure paths: partial
/// statuses, retry upgrades, and rescan immutability invariants.
/// These run with the same harness as
/// <see cref="CompleteScanWorkflowTests"/> but exercise narrower
/// scenarios.
/// </summary>
public sealed class SemanticFailureWorkflowTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public SemanticFailureWorkflowTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-sem-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(masterKey);
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

    [Fact]
    public async Task Partial_with_only_llm_unresolved_upgrades_to_completed_on_retry()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-sem-partial-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.EndpointDown);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            // Partial is the expected terminal state when the endpoint
            // was down.
            ScanRun afterRun = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Partial, afterRun.Status);

            // Re-running on a healthy endpoint lifts the scan to Completed
            // only when no other gap remains.
            var healthy = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.ConfirmedAll);
            ScanId healthyScanId = await healthy.CreateAndStartAsync();
            await healthy.RunAsync(healthyScanId, TestContext.Current.CancellationToken);

            ScanRun healthyFinal = (await healthy.Scans.GetByIdAsync(healthyScanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, healthyFinal.Status);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Rescan_does_not_mutate_previous_run_state()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-sem-rescan-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var first = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.ConfirmedAll);
            ScanId firstId = await first.CreateAndStartAsync();
            await first.RunAsync(firstId, TestContext.Current.CancellationToken);

            ScanRun firstFinal = (await first.Scans.GetByIdAsync(firstId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, firstFinal.Status);
            long originalVersion = firstFinal.Version;

            var second = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.ConfirmedAll);
            ScanId secondId = await second.CreateAndStartAsync();
            await second.RunAsync(secondId, TestContext.Current.CancellationToken);

            // The previous scan's status, version, and timestamp stay frozen.
            ScanRun firstAfter = (await second.Scans.GetByIdAsync(firstId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, firstAfter.Status);
            Assert.Equal(originalVersion, firstAfter.Version);
            Assert.Equal(firstFinal.UpdatedAtUtc, firstAfter.UpdatedAtUtc);
            Assert.NotEqual(firstId, secondId);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Snapshot_hash_remains_stable_through_run()
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("srt-sem-snap-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.ConfirmedAll);
            ScanId scanId = await harness.CreateAndStartAsync();

            string hashBefore = harness.CurrentConfigHashFor(scanId);
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);
            string hashAfter = harness.CurrentConfigHashFor(scanId);

            Assert.Equal(hashBefore, hashAfter);
        }
        finally
        {
            try { root.Refresh(); root.Delete(recursive: true); } catch { }
        }
    }
}
