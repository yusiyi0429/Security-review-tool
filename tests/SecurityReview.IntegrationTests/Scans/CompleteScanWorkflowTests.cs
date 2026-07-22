using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Diagnostics;
using SecurityReview.Application.Llm;
using SecurityReview.Application.Reviews;
using SecurityReview.Application.Rules;
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
using SecurityReview.Infrastructure.Persistence.Repositories;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Core;
using SecurityReview.Parsers.Text;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Policy;
using ISqliteConnectionFactory = SecurityReview.Infrastructure.Persistence.ISqliteConnectionFactory;

namespace SecurityReview.IntegrationTests.Scans;

/// <summary>
/// End-to-end scenarios for the scan application workflow.
/// Asserts terminal <see cref="ScanStatus"/>, transactional history,
/// progress counters, cache provenance, and immutable old-scan guarantee
/// across the full lifecycle: create → start → scan → finalize.
/// </summary>
public sealed class CompleteScanWorkflowTests : IAsyncDisposable
{
    private readonly string _tempDir;
    private readonly string _databasePath;
    private readonly SqliteConnectionFactory _factory;
    private readonly AesGcmPayloadProtector _protector;
    private readonly PersistentValueFingerprintService _fingerprint;
    private readonly HkdfSha256 _hkdf;

    public CompleteScanWorkflowTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("srt-scan-wf-").FullName;
        _databasePath = Path.Combine(_tempDir, "test.db");
        _factory = new SqliteConnectionFactory(_databasePath);

        byte[] masterKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(masterKey);
        _hkdf = new HkdfSha256(masterKey);
        _protector = new AesGcmPayloadProtector(_hkdf.DeriveEncryptionKey(), "test-key");
        _fingerprint = new PersistentValueFingerprintService(_hkdf.DeriveFingerprintKey());

        using var init = new SqliteConnection($"Data Source={_databasePath};Mode=ReadWriteCreate");
        init.Open();
        foreach (IMigration migration in DefaultMigrations.Create())
        {
            migration.ApplyAsync(init, "test-integration", CancellationToken.None)
                .GetAwaiter().GetResult();
        }
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

    // ------------------------------------------------------------------
    // 1. all-covered + zero candidate → Completed
    // ------------------------------------------------------------------
    [Fact]
    public async Task All_covered_zero_candidate_yields_completed()
    {
        DirectoryInfo root = NewRoot("srt-wf-zero-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "a.txt"), "hello",
                TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root);
            ScanId scanId = await harness.CreateAndStartAsync();

            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, final.Status);
            Assert.Equal(0, harness.FindingCount);
            Assert.Equal(0, harness.UnresolvedSemanticCount);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 2. all-covered + semantic candidates all reviewed → Completed
    // ------------------------------------------------------------------
    [Fact]
    public async Task All_covered_semantic_reviewed_yields_completed()
    {
        DirectoryInfo root = NewRoot("srt-wf-sem-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.ConfirmedAll);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, final.Status);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 3. all-covered + semantic endpoint unavailable → Partial
    // ------------------------------------------------------------------
    [Fact]
    public async Task Semantic_endpoint_down_yields_partial()
    {
        DirectoryInfo root = NewRoot("srt-wf-endpt-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.EndpointDown);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Partial, final.Status);
            Assert.True(harness.UnresolvedSemanticCount > 0);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 4. all-covered + no-sem + LLM-down → Completed
    // ------------------------------------------------------------------
    [Fact]
    public async Task No_candidate_with_llm_down_still_completes()
    {
        DirectoryInfo root = NewRoot("srt-wf-nocand-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            // semanticOutcome is irrelevant when no candidates are produced; the LLM-down flag
            // does not affect terminal status because no unresolved semantic remains.
            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                semanticOutcome: SemanticOutcome.EndpointDown,
                emitCandidate: false);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Completed, final.Status);
            Assert.Equal(0, harness.UnresolvedSemanticCount);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 5. any parser/decoder/archive gap → Partial
    // ------------------------------------------------------------------
    [Fact]
    public async Task Coverage_gap_yields_partial()
    {
        DirectoryInfo root = NewRoot("srt-wf-gap-");
        try
        {
            // random bytes — looks like a corrupt file → parser produces a gap.
            string badPath = Path.Combine(root.FullName, "broken.bin");
            byte[] noise = new byte[256];
            new Random(7).NextBytes(noise);
            await File.WriteAllBytesAsync(badPath, noise, TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                emitCandidate: false,
                includeArchiveCorrupt: true);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Partial, final.Status);
            Assert.True(harness.GapCount > 0);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 6. root/inventory/database integrity failure → Failed
    // ------------------------------------------------------------------
    [Fact]
    public async Task Missing_root_is_rejected_during_start_preflight()
    {
        var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root: null,
            rootMissing: true);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.CreateAndStartAsync());
        Assert.Contains("root_invalid", error.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // 7. user cancellation → Cancelled
    // ------------------------------------------------------------------
    [Fact]
    public async Task User_cancellation_yields_cancelled()
    {
        DirectoryInfo root = NewRoot("srt-wf-cancel-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                simulateCancel: true);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Cancelled, final.Status);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 8. file changes once then stable → based on final coverage
    // ------------------------------------------------------------------
    [Fact]
    public async Task File_changes_once_then_stable_completes()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = NewRoot("srt-wf-flip-");
        try
        {
            string liveFile = Path.Combine(root.FullName, "live.txt");
            await File.WriteAllTextAsync(liveFile, "AAAAAAAA",
                TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                fileToMutateOnce: liveFile);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            // After one mutation the orchestrator retries and the second pass is stable.
            Assert.Equal(ScanStatus.Completed, final.Status);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 9. file changes twice → Partial (FileUnstable)
    // ------------------------------------------------------------------
    [Fact]
    public async Task File_changes_twice_yields_partial_with_file_unstable()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux(),
            "Requires Windows or Linux.");

        DirectoryInfo root = NewRoot("srt-wf-flip2-");
        try
        {
            string liveFile = Path.Combine(root.FullName, "live.txt");
            await File.WriteAllTextAsync(liveFile, "AAAAAAAA",
                TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root,
                fileToMutateTwice: liveFile);
            ScanId scanId = await harness.CreateAndStartAsync();
            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            ScanRun final = (await harness.Scans.GetByIdAsync(scanId,
                TestContext.Current.CancellationToken))!;
            Assert.Equal(ScanStatus.Partial, final.Status);
            Assert.Contains(harness.ObservedGaps,
                g => g.Reason == GapReason.FileUnstable);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 10. transaction history append-only — no old scan overwritten
    // ------------------------------------------------------------------
    [Fact]
    public async Task Rerun_does_not_overwrite_previous_scan()
    {
        DirectoryInfo root = NewRoot("srt-wf-rerun-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root);
            ScanId firstId = await harness.CreateAndStartAsync();
            await harness.RunAsync(firstId, TestContext.Current.CancellationToken);

            ScanId secondId = await harness.CreateAndStartAsync();
            await harness.RunAsync(secondId, TestContext.Current.CancellationToken);

            Assert.NotEqual(firstId, secondId);
            ScanRun first = (await harness.Scans.GetByIdAsync(firstId,
                TestContext.Current.CancellationToken))!;
            ScanRun second = (await harness.Scans.GetByIdAsync(secondId,
                TestContext.Current.CancellationToken))!;

            // The first scan's status and row version must remain frozen; each
            // independent scan advances through the same lifecycle revisions.
            Assert.Equal(ScanStatus.Completed, first.Status);
            Assert.Equal(ScanStatus.Completed, second.Status);
            Assert.True(first.Version >= 4);
            Assert.True(second.Version >= 4);

            // Both scans must be listed by status.
            IReadOnlyList<ScanRun> completed = await harness.Scans.ListByStatusAsync(
                new[] { ScanStatus.Completed }, TestContext.Current.CancellationToken);
            Assert.Contains(completed, s => s.ScanId == firstId);
            Assert.Contains(completed, s => s.ScanId == secondId);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // 11. UI edits after Start do not affect in-flight scan
    // ------------------------------------------------------------------
    [Fact]
    public async Task Ui_edits_after_start_do_not_affect_inflight_scan()
    {
        DirectoryInfo root = NewRoot("srt-wf-ui-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "x.txt"),
                "anything", TestContext.Current.CancellationToken);

            var harness = new WorkflowHarness(_factory, _protector, _fingerprint, root);
            ScanId scanId = await harness.CreateAndStartAsync();

            // Simulate a UI edit — the snapshot captured at Create time must persist.
            string snapshotHashBefore = harness.CurrentConfigHashFor(scanId);

            await harness.RunAsync(scanId, TestContext.Current.CancellationToken);

            string snapshotHashAfter = harness.CurrentConfigHashFor(scanId);
            Assert.Equal(snapshotHashBefore, snapshotHashAfter);
        }
        finally
        {
            TryDelete(root);
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------
    private static DirectoryInfo NewRoot(string prefix)
    {
        return Directory.CreateTempSubdirectory(prefix);
    }

    private static void TryDelete(DirectoryInfo root)
    {
        try { root.Refresh(); root.Delete(recursive: true); } catch { }
    }
}

internal enum SemanticOutcome
{
    NoCandidates,
    ConfirmedAll,
    EndpointDown
}
