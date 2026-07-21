using System.Security.Principal;
using SecurityReview.Application.Abstractions;

namespace SecurityReview.Infrastructure.Windows.Identity;

/// <summary>
/// Provides the current Windows user identity via <see cref="WindowsIdentity.GetCurrent()"/>.
/// Returns null when not running on Windows or when the identity cannot be resolved.
/// </summary>
public sealed class WindowsIdentityProvider : IWindowsIdentityProvider
{
    public WindowsIdentityInfo? GetCurrentUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity?.User is null)
                return null;

            return new WindowsIdentityInfo(
                identity.User.Value,
                identity.Name ?? identity.User.Value);
        }
        catch
        {
            return null;
        }
    }
}
