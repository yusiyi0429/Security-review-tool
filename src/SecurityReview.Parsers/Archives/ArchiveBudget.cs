using SecurityReview.Domain.Scans;

namespace SecurityReview.Parsers.Archives;

/// <summary>
/// Thread-safe, task-wide budget that bounds recursive archive expansion.
/// A single <see cref="ArchiveBudget"/> is shared across all archive-
/// format parsers within one worker task. All counter mutations use
/// <see cref="Interlocked"/> operations so that concurrent parsers
/// can call <see cref="TryReserve"/> without external locks.
/// </summary>
public sealed class ArchiveBudget
{
    /// <summary>Hard cap on total expanded bytes (50 GiB).</summary>
    public const long MaxExpandedBytesCap = 53_687_091_200L;

    /// <summary>Maximum number of archive entries across all archives.</summary>
    public const int MaxEntries = 100_000;

    /// <summary>Maximum entry depth (root archive = depth 1).</summary>
    public const int MaxDepth = 5;

    /// <summary>Maximum expanded bytes for a single entry (4 GiB).</summary>
    public const long MaxBytesPerEntry = 4_294_967_296L;

    private int _reservedEntries;
    private long _reservedExpandedBytes;
    private long _reservedCompressedBytes;

    /// <summary>Aggregate cap computed from the total brokered input size.</summary>
    public long ResolvedExpandedLimit { get; }

    /// <summary>
    /// Constructs the task-wide budget.
    /// </summary>
    /// <param name="totalBrokeredInputBytes">Sum of <c>DeclaredLength</c> for all
    /// top-level files assigned to this task.</param>
    public ArchiveBudget(long totalBrokeredInputBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(totalBrokeredInputBytes);

        ResolvedExpandedLimit = ComputeExpandedLimit(totalBrokeredInputBytes);
    }

    /// <summary>
    /// Attempts to reserve budget for <paramref name="entryCount"/> archive entries.
    /// Returns a result describing which limit was hit on failure, or a success
    /// token that the caller must pass to <see cref="Release"/> on rollback.
    /// </summary>
    public ReserveResult TryReserve(int entryCount, long declaredBytes, long compressedBytes, int depth)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(entryCount);
        ArgumentOutOfRangeException.ThrowIfNegative(declaredBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(compressedBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(depth);

        // --- depth check ---
        if (depth > MaxDepth)
        {
            return ReserveResult.DepthExceeded(depth);
        }

        // --- per-entry check ---
        if (declaredBytes > MaxBytesPerEntry)
        {
            return ReserveResult.EntryTooLarge(declaredBytes);
        }

        // --- entry count check ---
        int currentEntries = Interlocked.Add(ref _reservedEntries, entryCount);
        if (currentEntries > MaxEntries)
        {
            // Roll back the entry count addition
            Interlocked.Add(ref _reservedEntries, -entryCount);
            return ReserveResult.EntryCountExceeded(currentEntries);
        }

        // --- expanded bytes check ---
        long currentExpanded;
        try
        {
            currentExpanded = Interlocked.Add(ref _reservedExpandedBytes, declaredBytes);
        }
        catch (OverflowException)
        {
            // Roll back entry count only (expanded bytes couldn't have been added)
            Interlocked.Add(ref _reservedEntries, -entryCount);
            return ReserveResult.ExpandedBytesExceeded(declaredBytes);
        }

        if (currentExpanded > ResolvedExpandedLimit)
        {
            // Roll back both
            Interlocked.Add(ref _reservedExpandedBytes, -declaredBytes);
            Interlocked.Add(ref _reservedEntries, -entryCount);
            return ReserveResult.ExpandedBytesExceeded(currentExpanded);
        }

        // --- compressed bytes (informational, tracked but not capped) ---
        try
        {
            Interlocked.Add(ref _reservedCompressedBytes, compressedBytes);
        }
        catch (OverflowException)
        {
            // Compressed bytes overflow: record as ArchiveLimit gap.
            // Roll back all prior reservations.
            Interlocked.Add(ref _reservedExpandedBytes, -declaredBytes);
            Interlocked.Add(ref _reservedEntries, -entryCount);
            return ReserveResult.Overflow("compressed_bytes_overflow");
        }

        return ReserveResult.Success(entryCount, declaredBytes);
    }

    /// <summary>
    /// Releases previously reserved bytes and entries (used when a stream
    /// produces fewer bytes than declared, or for rollback).
    /// </summary>
    public void Release(long declaredBytes, long compressedBytes)
    {
        if (declaredBytes > 0)
            Interlocked.Add(ref _reservedExpandedBytes, -declaredBytes);
        if (compressedBytes > 0)
            Interlocked.Add(ref _reservedCompressedBytes, -compressedBytes);
    }

    /// <summary>
    /// Reads the current reserved entry count.
    /// </summary>
    public int SnapshotEntries() => Volatile.Read(ref _reservedEntries);

    /// <summary>
    /// Reads the current reserved expanded bytes.
    /// </summary>
    public long SnapshotExpandedBytes() => Interlocked.Read(ref _reservedExpandedBytes);

    private static long ComputeExpandedLimit(long totalBrokeredInputBytes)
    {
        // saturatingMultiply(totalBrokeredInputBytes, 100)
        long product;
        try
        {
            product = checked(totalBrokeredInputBytes * 100);
        }
        catch (OverflowException)
        {
            product = long.MaxValue;
        }

        return Math.Min(MaxExpandedBytesCap, product);
    }
}

/// <summary>
/// Result of a <see cref="ArchiveBudget.TryReserve"/> call.
/// </summary>
public readonly record struct ReserveResult
{
    private ReserveResult(bool succeeded, string? detailCode, long value, int depth, int entryCount)
    {
        Succeeded = succeeded;
        DetailCode = detailCode;
        Value = value;
        Depth = depth;
        ReservedEntryCount = entryCount;
    }

    /// <summary>True when the reservation was accepted.</summary>
    public bool Succeeded { get; }

    /// <summary>Machine-readable detail code for gap creation.</summary>
    public string? DetailCode { get; }

    /// <summary>Numeric value associated with the limit check.</summary>
    public long Value { get; }

    /// <summary>Depth that was checked (only meaningful for depth-exceeded).</summary>
    public int Depth { get; }

    /// <summary>Number of entries reserved (only meaningful for success).</summary>
    public int ReservedEntryCount { get; }

    public GapReason? ToGapReason() => DetailCode switch
    {
        "depth_exceeded" => GapReason.ArchiveLimit,
        "entry_count_exceeded" => GapReason.ArchiveLimit,
        "entry_too_large" => GapReason.ArchiveLimit,
        "expanded_bytes_exceeded" => GapReason.ArchiveLimit,
        "compressed_bytes_overflow" => GapReason.ArchiveLimit,
        _ => null,
    };

    public static ReserveResult Success(int entryCount, long declaredBytes) =>
        new(true, null, declaredBytes, 0, entryCount);

    public static ReserveResult DepthExceeded(int depth) =>
        new(false, "depth_exceeded", depth, depth, 0);

    public static ReserveResult EntryCountExceeded(int current) =>
        new(false, "entry_count_exceeded", current, 0, 0);

    public static ReserveResult EntryTooLarge(long declaredBytes) =>
        new(false, "entry_too_large", declaredBytes, 0, 0);

    public static ReserveResult ExpandedBytesExceeded(long current) =>
        new(false, "expanded_bytes_exceeded", current, 0, 0);

    public static ReserveResult Overflow(string code) =>
        new(false, code, 0, 0, 0);
}
