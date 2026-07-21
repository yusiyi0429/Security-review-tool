namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Provides the current Windows user identity (SID and display name) for
/// audit attribution in review decisions and exception grants.
/// </summary>
public interface IWindowsIdentityProvider
{
    /// <summary>
    /// Returns the current Windows user's SID string (e.g. "S-1-5-21-...")
    /// and display name, or null when not running on Windows.
    /// </summary>
    WindowsIdentityInfo? GetCurrentUser();
}

/// <summary>
/// Captured Windows identity information for audit attribution.
/// </summary>
public sealed record WindowsIdentityInfo(
    string UserSid,
    string DisplayName);
