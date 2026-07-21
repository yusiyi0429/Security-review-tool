using SecurityReview.Application.Scans;

namespace SecurityReview.UnitTests.Scans;

public sealed class ProgressAggregatorTests
{
    [Fact]
    public async Task emits_latest_snapshot()
    {
        using var aggregator = new ProgressAggregator();
        aggregator.Start();

        aggregator.Post(new ScanProgress(ScanStage.Running, 10, 5, 2, 1000, 500, 0, 0, 0, 3, 5));

        var progressList = new List<ScanProgress>();
        await foreach (ScanProgress p in aggregator.Updates.ReadAllAsync())
        {
            progressList.Add(p);
            if (progressList.Count >= 1) break;
        }

        await aggregator.CompleteAsync();

        Assert.NotEmpty(progressList);
        Assert.Equal(10, progressList[^1].DiscoveredFiles);
        Assert.Equal(5, progressList[^1].ProcessedFiles);
    }

    [Fact]
    public async Task multiple_posts_are_coalesced()
    {
        using var aggregator = new ProgressAggregator();
        aggregator.Start();

        for (int i = 0; i < 10; i++)
        {
            aggregator.Post(new ScanProgress(ScanStage.Running, i + 1, i, 0, 100, i * 10, 0, 0, 0, 1, i));
        }

        // Wait for coalescing to emit.
        await Task.Delay(600);

        aggregator.Post(new ScanProgress(ScanStage.Completed, 10, 9, 1, 100, 90, 0, 0, 0, 0, 10));

        var progressList = new List<ScanProgress>();
        await foreach (ScanProgress p in aggregator.Updates.ReadAllAsync())
        {
            progressList.Add(p);
            if (p.Stage == ScanStage.Completed) break;
        }

        await aggregator.CompleteAsync();

        // Should have fewer updates than posts (coalescing worked).
        Assert.True(progressList.Count < 11);
        Assert.Contains(progressList, p => p.Stage == ScanStage.Completed);
    }

    [Fact]
    public void empty_progress_has_no_sensitive_data()
    {
        var empty = ScanProgress.Empty;

        Assert.Equal(ScanStage.Draft, empty.Stage);
        Assert.Equal(0, empty.DiscoveredFiles);
        Assert.Equal(0, empty.CurrentFileOrdinal);
        // No path, content, or secret fields exist on ScanProgress.
        var propertyNames = empty.GetType().GetProperties()
            .Select(p => p.Name);
        Assert.DoesNotContain(propertyNames,
            n => n.Contains("Path", StringComparison.OrdinalIgnoreCase)
                 || n.Contains("Content", StringComparison.OrdinalIgnoreCase)
                 || n.Contains("Secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task complete_without_start_produces_no_updates()
    {
        using var aggregator = new ProgressAggregator();
        // No Start() call. Complete immediately.
        await aggregator.CompleteAsync();

        var progressList = new List<ScanProgress>();
        await foreach (ScanProgress _ in aggregator.Updates.ReadAllAsync())
        {
            progressList.Add(_);
        }

        Assert.Empty(progressList);
    }
}
