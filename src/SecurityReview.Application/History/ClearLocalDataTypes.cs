namespace SecurityReview.Application.History;

/// <summary>
/// Result category status for the clear-local-data operation.
/// </summary>
public enum ClearCategoryStatus
{
    Succeeded,
    Failed,
    Skipped,
}

/// <summary>
/// Result of a clear-local-data operation. Paths are intentionally excluded
/// from this result.
/// </summary>
public sealed record ClearLocalDataResult(
    bool AllSucceeded,
    int ScanCountAtConfirmation,
    IReadOnlyDictionary<string, ClearCategoryStatus> Categories)
{
    /// <summary>
    /// Returns the UI-facing message. When all categories succeeded this is
    /// "本工具本地数据已清除"; otherwise it lists the failed categories.
    /// </summary>
    public string UserMessage => AllSucceeded
        ? "本工具本地数据已清除"
        : $"部分数据清除失败，请手动重试以下类别: {string.Join(", ", FailedCategories())}";

    private IEnumerable<string> FailedCategories() =>
        Categories.Where(kv => kv.Value == ClearCategoryStatus.Failed).Select(kv => kv.Key);
}

/// <summary>
/// Parameter object for the clear-local-data command.
/// </summary>
public sealed record ClearLocalDataCommand(bool Confirmed, int ScanCount)
{
    /// <summary>
    /// Creates a denied command (user did not confirm).
    /// </summary>
    public static ClearLocalDataCommand Denied => new(false, 0);
}
