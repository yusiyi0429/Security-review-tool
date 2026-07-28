namespace SecurityReview.Infrastructure.Updates;

/// <summary>
/// Raised when a downloaded update artifact fails integrity verification:
/// SHA-256 mismatch against the published sidecar, an unparseable or
/// oversized sidecar, an installer exceeding the size cap, or a redirect
/// chain violation. The partial or completed download is always deleted
/// before this exception escapes; the artifact must never be executed.
/// Carries no URLs, paths, or hash values in its message.
/// </summary>
public sealed class UpdateVerificationException : Exception
{
    public UpdateVerificationException(string message)
        : base(message)
    {
    }

    public UpdateVerificationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
