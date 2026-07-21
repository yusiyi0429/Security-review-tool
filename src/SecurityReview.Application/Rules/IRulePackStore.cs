using SecurityReview.RulePack.Packaging;

namespace SecurityReview.Application.Rules;

/// <summary>
/// Atomic file storage for rule pack ZIP packages.
/// Stages under a temp directory, validates, flushes, and moves to the
/// immutable packages store. Manages an <c>active.json</c> pointer.
/// </summary>
public interface IRulePackStore
{
    /// <summary>
    /// Stores a validated rule pack ZIP. On success returns the final package path.
    /// </summary>
    Task<StoreResult> StoreAsync(
        byte[] zipBytes,
        RulePackManifest manifest,
        string sha256,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the current active pointer, or <c>null</c> if none exists.
    /// </summary>
    Task<ActivePointer?> GetActiveAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Atomically replaces the active pointer.
    /// </summary>
    Task SetActiveAsync(ActivePointer activePointer, CancellationToken cancellationToken);

    /// <summary>
    /// Recovers from interrupted staging — deletes leftover staging directories.
    /// </summary>
    bool TryRecoverStaging();
}

/// <summary>
/// Result of a store operation.
/// </summary>
public sealed record StoreResult(bool Success, string PackagePath);

/// <summary>
/// Pointer to the currently active rule pack.
/// </summary>
public sealed record ActivePointer
{
    public string RulePackId { get; init; } = "";
    public string Version { get; init; } = "";
    public string Sha256 { get; init; } = "";
}
