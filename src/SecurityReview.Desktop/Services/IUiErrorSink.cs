namespace SecurityReview.Desktop.Services;

/// <summary>
/// Receives typed, stable error codes from async commands
/// and the UI exception boundary. The public surface is closed:
/// only a stable <paramref name="code"/> and a sanitized
/// <paramref name="message"/> that contains no raw stack, path, or
/// value is ever passed to the UI.
/// </summary>
public interface IUiErrorSink
{
    /// <summary>
    /// Reports a user-visible error. <paramref name="code"/> is a
    /// stable, machine-readable string (e.g. "command_error",
    /// "sandbox_unavailable"). <paramref name="message"/> is a
    /// sanitized, localizable message. Neither contains raw exception
    /// text, stack frames, file paths, or confidential values.
    /// </summary>
    void Report(string code, string message);
}
