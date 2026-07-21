using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.History;

/// <summary>
/// Defines how long scan history is retained before automatic cleanup.
/// </summary>
public enum RetentionPeriod
{
    /// <summary>Scans older than 30 days are eligible for deletion.</summary>
    Days30 = 30,

    /// <summary>Scans older than 90 days are eligible for deletion.</summary>
    Days90 = 90,

    /// <summary>Scans older than 180 days are eligible for deletion.</summary>
    Days180 = 180,

    /// <summary>Scans are never automatically deleted.</summary>
    Permanent = 0,
}

/// <summary>
/// Pure functions for evaluating whether a scan is expired under a
/// retention period. All comparisons are exact: a scan whose
/// <see cref="ScanRun.CreatedAtUtc"/> is exactly <c>now - period</c>
/// is considered expired.
/// </summary>
public static class RetentionPolicy
{
    /// <summary>
    /// Returns <c>true</c> when <paramref name="scan"/> should be deleted
    /// according to <paramref name="period"/>.
    /// </summary>
    public static bool IsExpired(ScanRun scan, RetentionPeriod period, DateTimeOffset now)
    {
        if (period == RetentionPeriod.Permanent)
            return false;

        var age = TimeSpan.FromDays((int)period);
        return (now - scan.CreatedAtUtc) >= age;
    }

    /// <summary>
    /// Returns the creation timestamp at or before which scans are
    /// eligible for deletion.
    /// </summary>
    public static DateTimeOffset ExpiryThreshold(RetentionPeriod period, DateTimeOffset now)
    {
        if (period == RetentionPeriod.Permanent)
            return DateTimeOffset.MinValue;

        return now - TimeSpan.FromDays((int)period);
    }
}
