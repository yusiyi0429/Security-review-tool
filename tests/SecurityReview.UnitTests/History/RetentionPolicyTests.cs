using SecurityReview.Application.History;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.UnitTests.History;

public sealed class RetentionPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    private static ScanRun NewScan(DateTimeOffset createdAt) =>
        new(
            ScanId: new ScanId(Guid.NewGuid()),
            Status: ScanStatus.Completed,
            CreatedAtUtc: createdAt,
            UpdatedAtUtc: createdAt,
            RuleFingerprint: "hash",
            ClientFingerprint: "1.0",
            PipelineFingerprint: "pipe",
            PlannedCount: 100,
            Version: 1);

    // ---------- 30-day retention ----------

    [Fact]
    public void Days30_expires_scan_exactly_at_boundary()
    {
        var scan = NewScan(Now.AddDays(-30));
        Assert.True(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days30, Now));
    }

    [Fact]
    public void Days30_keeps_scan_one_second_before_boundary()
    {
        var scan = NewScan(Now.AddDays(-30).AddSeconds(1));
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days30, Now));
    }

    [Fact]
    public void Days30_keeps_recent_scan()
    {
        var scan = NewScan(Now.AddDays(-5));
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days30, Now));
    }

    // ---------- 90-day retention ----------

    [Fact]
    public void Days90_expires_scan_exactly_at_boundary()
    {
        var scan = NewScan(Now.AddDays(-90));
        Assert.True(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days90, Now));
    }

    [Fact]
    public void Days90_keeps_scan_one_second_before_boundary()
    {
        var scan = NewScan(Now.AddDays(-90).AddSeconds(1));
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days90, Now));
    }

    // ---------- 180-day retention ----------

    [Fact]
    public void Days180_expires_scan_exactly_at_boundary()
    {
        var scan = NewScan(Now.AddDays(-180));
        Assert.True(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days180, Now));
    }

    [Fact]
    public void Days180_keeps_scan_one_second_before_boundary()
    {
        var scan = NewScan(Now.AddDays(-180).AddSeconds(1));
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Days180, Now));
    }

    // ---------- Permanent ----------

    [Fact]
    public void Permanent_never_expires_old_scan()
    {
        var scan = NewScan(Now.AddDays(-1000));
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Permanent, Now));
    }

    [Fact]
    public void Permanent_never_expires_new_scan()
    {
        var scan = NewScan(Now);
        Assert.False(RetentionPolicy.IsExpired(scan, RetentionPeriod.Permanent, Now));
    }

    // ---------- Expiry threshold ----------

    [Fact]
    public void ExpiryThreshold_Days30_returns_30_days_ago()
    {
        var threshold = RetentionPolicy.ExpiryThreshold(RetentionPeriod.Days30, Now);
        Assert.Equal(Now.AddDays(-30), threshold);
    }

    [Fact]
    public void ExpiryThreshold_Days90_returns_90_days_ago()
    {
        var threshold = RetentionPolicy.ExpiryThreshold(RetentionPeriod.Days90, Now);
        Assert.Equal(Now.AddDays(-90), threshold);
    }

    [Fact]
    public void ExpiryThreshold_Days180_returns_180_days_ago()
    {
        var threshold = RetentionPolicy.ExpiryThreshold(RetentionPeriod.Days180, Now);
        Assert.Equal(Now.AddDays(-180), threshold);
    }

    [Fact]
    public void ExpiryThreshold_Permanent_returns_min_value()
    {
        var threshold = RetentionPolicy.ExpiryThreshold(RetentionPeriod.Permanent, Now);
        Assert.Equal(DateTimeOffset.MinValue, threshold);
    }
}
