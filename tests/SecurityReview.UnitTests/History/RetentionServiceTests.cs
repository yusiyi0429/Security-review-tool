using SecurityReview.Application.Abstractions;
using SecurityReview.Application.History;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.History;

public sealed class RetentionServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    private static ScanRun NewScan(DateTimeOffset createdAt, ScanStatus status = ScanStatus.Completed) =>
        new(
            ScanId: new ScanId(Guid.NewGuid()),
            Status: status,
            CreatedAtUtc: createdAt,
            UpdatedAtUtc: createdAt,
            RuleFingerprint: "hash",
            ClientFingerprint: "1.0",
            PipelineFingerprint: "pipe",
            PlannedCount: 100,
            Version: 1);

    [Fact]
    public async Task PreviewExpired_returns_empty_for_permanent()
    {
        var repo = new StubScanRepository(
            NewScan(Now),
            NewScan(Now.AddDays(-365))
        );
        var maintenance = new StubMaintenanceService();
        var service = new RetentionService(repo, maintenance);

        var expired = await service.PreviewExpiredAsync(RetentionPeriod.Permanent);

        Assert.Empty(expired);
    }

    [Fact]
    public async Task PreviewExpired_returns_expired_scans_only()
    {
        var old = NewScan(Now.AddDays(-40));
        var recent = NewScan(Now.AddDays(-5));
        var repo = new StubScanRepository(old, recent);
        var maintenance = new StubMaintenanceService();
        var service = new RetentionService(repo, maintenance);

        var expired = await service.PreviewExpiredAsync(RetentionPeriod.Days30);

        Assert.Single(expired);
        Assert.Contains(old.ScanId, expired);
    }

    [Fact]
    public async Task PurgeExpired_returns_can_delete_false_for_permanent()
    {
        var repo = new StubScanRepository(NewScan(Now.AddDays(-100)));
        var maintenance = new StubMaintenanceService();
        var service = new RetentionService(repo, maintenance);

        var result = await service.PurgeExpiredAsync(RetentionPeriod.Permanent);

        Assert.False(result.CanDelete);
        Assert.Equal(0, result.Deleted);
        Assert.Equal(0, result.Preserved);
    }

    [Fact]
    public async Task PurgeExpired_delegates_to_maintenance_service()
    {
        var expired = NewScan(Now.AddDays(-40));
        var kept = NewScan(Now.AddDays(-5));
        var repo = new StubScanRepository(expired, kept);
        var maintenance = new StubMaintenanceService();
        var service = new RetentionService(repo, maintenance);

        var result = await service.PurgeExpiredAsync(RetentionPeriod.Days30);

        Assert.True(result.CanDelete);
        Assert.Equal(1, result.Deleted);
        Assert.Equal(1, result.Preserved);
        Assert.Single(maintenance.DeletedScanIds);
        Assert.Equal(expired.ScanId, maintenance.DeletedScanIds[0]);
    }

    [Fact]
    public async Task PurgeExpired_deletes_nothing_when_all_are_recent()
    {
        var recent = NewScan(Now.AddDays(-2));
        var repo = new StubScanRepository(recent);
        var maintenance = new StubMaintenanceService();
        var service = new RetentionService(repo, maintenance);

        var result = await service.PurgeExpiredAsync(RetentionPeriod.Days30);

        Assert.True(result.CanDelete);
        Assert.Equal(0, result.Deleted);
        Assert.Equal(1, result.Preserved);
        Assert.Empty(maintenance.DeletedScanIds);
    }

    // ---------- Stubs ----------

    private sealed class StubScanRepository : IScanRepository
    {
        private readonly List<ScanRun> _scans;

        public StubScanRepository(params ScanRun[] scans) => _scans = scans.ToList();

        public Task InsertAsync(ScanRun scan, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ScanRun?> GetByIdAsync(ScanId scanId, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ScanRun>> ListAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<ScanRun>>(_scans);
        public Task<bool> TryTransitionAsync(ScanId scanId, ScanStatus expectedStatus, long expectedVersion,
            ScanStatus nextStatus, CancellationToken ct = default) => throw new NotSupportedException();
        public Task UpdateAsync(ScanRun scan, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ScanRun>> ListByStatusAsync(IReadOnlyList<ScanStatus> statuses,
            CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ScanRun?> FindLatestPreviousAsync(string activeRulePackHash, string endpointFingerprint,
            CancellationToken ct = default) => throw new NotSupportedException();
    }

    private sealed class StubMaintenanceService : IDatabaseMaintenanceService
    {
        public List<ScanId> DeletedScanIds { get; } = [];

        public Task<int> DeleteExpiredScansAsync(IReadOnlyList<ScanId> scanIds, CancellationToken ct = default)
        {
            DeletedScanIds.AddRange(scanIds);
            return Task.FromResult(scanIds.Count);
        }

        public Task<int> DeleteUnreferencedCacheAsync(DateTimeOffset? lastUsedThreshold, CancellationToken ct = default) =>
            Task.FromResult(0);

        public Task CheckpointWalAsync(CancellationToken ct = default) => Task.CompletedTask;

        public Task<VacuumResult> TryVacuumAsync(bool hasActiveScan, CancellationToken ct = default) =>
            Task.FromResult(VacuumResult.AppliedSuccessfully());
    }
}
