namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Provides free disk space information for cache budget calculations.
/// Injected so tests can control the capacity independently of the real
/// filesystem.
/// </summary>
public interface IDiskCapacityProvider
{
    /// <summary>Returns the number of free bytes on the target volume.</summary>
    long GetFreeBytes();
}
