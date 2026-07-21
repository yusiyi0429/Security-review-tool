namespace SecurityReview.UnitTests.Parsers;

using SecurityReview.Parsers.Archives;

public sealed class ArchiveBudgetTests
{
    [Fact]
    public void resolved_limit_is_min_of_cap_and_100x_input()
    {
        var budget = new ArchiveBudget(1_000_000);
        Assert.Equal(100_000_000L, budget.ResolvedExpandedLimit);

        var budgetLarge = new ArchiveBudget(10_000_000_000L);
        // 100 * 10GB = 1TB > 50 GiB cap, so cap wins
        Assert.Equal(ArchiveBudget.MaxExpandedBytesCap, budgetLarge.ResolvedExpandedLimit);
    }

    [Fact]
    public void zero_input_permits_metadata_only()
    {
        var budget = new ArchiveBudget(0);
        Assert.Equal(0, budget.ResolvedExpandedLimit);
        Assert.Equal(0, budget.SnapshotEntries());
        Assert.Equal(0, budget.SnapshotExpandedBytes());
    }

    [Fact]
    public void negative_input_throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ArchiveBudget(-1));
    }

    [Fact]
    public void try_reserve_within_limits_succeeds()
    {
        var budget = new ArchiveBudget(1_000_000);
        var result = budget.TryReserve(1, 10_000, 50_000, 1);

        Assert.True(result.Succeeded);
        Assert.Equal(1, budget.SnapshotEntries());
        Assert.Equal(10_000, budget.SnapshotExpandedBytes());
    }

    [Fact]
    public void depth_6_rejected()
    {
        var budget = new ArchiveBudget(1_000_000);
        var result = budget.TryReserve(1, 100, 100, 6);

        Assert.False(result.Succeeded);
        Assert.Equal("depth_exceeded", result.DetailCode);
        Assert.Equal(0, budget.SnapshotEntries());
    }

    [Fact]
    public void depth_5_accepted()
    {
        var budget = new ArchiveBudget(1_000_000);
        var result = budget.TryReserve(1, 100, 100, 5);

        Assert.True(result.Succeeded);
        Assert.Equal(1, budget.SnapshotEntries());
    }

    [Fact]
    public void entry_100000_accepted_100001_rejected()
    {
        var budget = new ArchiveBudget(long.MaxValue / 100);

        // Reserve all 100K entries
        var result = budget.TryReserve(100_000, 100_000_000, 0, 1);
        Assert.True(result.Succeeded);
        Assert.Equal(100_000, budget.SnapshotEntries());

        // One more should be rejected
        var overflow = budget.TryReserve(1, 100, 0, 1);
        Assert.False(overflow.Succeeded);
        Assert.Equal("entry_count_exceeded", overflow.DetailCode);
    }

    [Fact]
    public void entry_4gib_accepted_4gib_plus_one_rejected()
    {
        var budget = new ArchiveBudget(long.MaxValue / 100);
        long fourGiB = ArchiveBudget.MaxBytesPerEntry;

        var ok = budget.TryReserve(1, fourGiB, fourGiB, 1);
        Assert.True(ok.Succeeded);

        var tooBig = budget.TryReserve(1, fourGiB + 1, fourGiB + 1, 1);
        Assert.False(tooBig.Succeeded);
        Assert.Equal("entry_too_large", tooBig.DetailCode);
    }

    [Fact]
    public void expanded_bytes_limit_enforced()
    {
        var budget = new ArchiveBudget(1_000_000); // limit = 100MB

        var ok = budget.TryReserve(1, 50_000_000, 50_000_000, 1);
        Assert.True(ok.Succeeded);

        // Second reserve of 60MB pushes past 100MB limit
        var tooBig = budget.TryReserve(1, 60_000_000, 60_000_000, 1);
        Assert.False(tooBig.Succeeded);
        Assert.Equal("expanded_bytes_exceeded", tooBig.DetailCode);

        // First reserve should still be counted
        Assert.Equal(1, budget.SnapshotEntries());
        Assert.Equal(50_000_000, budget.SnapshotExpandedBytes());
    }

    [Fact]
    public void aggregate_50gib_cap_enforced()
    {
        var budget = new ArchiveBudget(long.MaxValue / 100);
        long twoGB = 2_000_000_000L;

        // Reserve 26 entries at 2 GB each = 52 GB > 50 GiB cap
        // 50 GiB cap = 53,687,091,200; 26 * 2GB = 52,000,000,000 < cap
        // 27 * 2GB = 54,000,000,000 > cap
        for (int i = 0; i < 26; i++)
        {
            var ok = budget.TryReserve(1, twoGB, 0, 1);
            Assert.True(ok.Succeeded);
        }

        Assert.Equal(26, budget.SnapshotEntries());
        Assert.Equal(52_000_000_000L, budget.SnapshotExpandedBytes());

        // One more should exceed 50 GiB cap
        var overflow = budget.TryReserve(1, twoGB, 0, 1);
        Assert.False(overflow.Succeeded);
        Assert.Equal("expanded_bytes_exceeded", overflow.DetailCode);
    }

    [Fact]
    public void release_returns_bytes()
    {
        var budget = new ArchiveBudget(1_000_000);
        var result = budget.TryReserve(1, 50_000, 25_000, 1);

        Assert.True(result.Succeeded);
        Assert.Equal(50_000, budget.SnapshotExpandedBytes());

        budget.Release(20_000, 10_000);

        Assert.Equal(30_000, budget.SnapshotExpandedBytes());
    }

    [Fact]
    public async Task concurrent_reservations_are_atomic()
    {
        var budget = new ArchiveBudget(long.MaxValue / 100);
        int threads = 10;
        int perThread = 10;
        var barrier = new Barrier(threads);
        var tasks = new Task[threads];

        for (int t = 0; t < threads; t++)
        {
            tasks[t] = Task.Run(() =>
            {
                barrier.SignalAndWait();
                for (int i = 0; i < perThread; i++)
                {
                    budget.TryReserve(1, 100, 100, 1);
                }
            });
        }

        await Task.WhenAll(tasks);
        Assert.Equal(threads * perThread, budget.SnapshotEntries());
        Assert.Equal(threads * perThread * 100L, budget.SnapshotExpandedBytes());
    }

    [Fact]
    public void virtual_path_rejects_traversal()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("../etc/passwd", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_absolute()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("/etc/passwd", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_drive_letter()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("C:/Windows/win.ini", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_nul()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("file\0name.txt", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_percent_encoded()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("file%20name.txt", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_unpaired_surrogate()
    {
        // Build a string with an unpaired high surrogate at position 4
        char[] chars = "file.txt".ToCharArray();
        Array.Resize(ref chars, chars.Length + 1);
        Array.Copy(chars, 4, chars, 5, chars.Length - 5);
        chars[4] = '\uD800';  // unpaired high surrogate
        string bad = new string(chars);
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry(bad, "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_accepts_normal_name()
    {
        string result = VirtualPath.ParseEntry("readme.txt", "outer.zip", 0);
        Assert.Equal("outer.zip!/readme.txt", result);
    }

    [Fact]
    public void virtual_path_normalizes_backslash()
    {
        string result = VirtualPath.ParseEntry("dir\\file.txt", "outer.zip", 0);
        Assert.Equal("outer.zip!/dir/file.txt", result);
    }

    [Fact]
    public void virtual_path_rejects_too_long()
    {
        string longName = new string('a', 5000);
        Assert.Throws<FormatException>(() =>
            VirtualPath.ParseEntry(longName, "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_empty()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_rejects_dot_segment()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("./config", "outer.zip", 0));
    }

    [Fact]
    public void virtual_path_double_separator_rejected()
    {
        Assert.Throws<ArgumentException>(() =>
            VirtualPath.ParseEntry("dir//file.txt", "outer.zip", 0));
    }
}
