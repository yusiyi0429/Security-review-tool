namespace SecurityReview.Infrastructure.Windows;

// Carries only the API name and the numeric error code; never paths, SIDs,
// or other sandbox-internal detail.
public sealed class WindowsSecurityException : Exception
{
    public WindowsSecurityException(string apiName, long errorCode)
        : base(FormattableString.Invariant($"{apiName} failed with error 0x{errorCode:X8}."))
    {
        ApiName = apiName;
        ErrorCode = errorCode;
    }

    public string ApiName { get; }
    public long ErrorCode { get; }
}
