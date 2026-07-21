using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;

namespace SecurityReview.Infrastructure.Diagnostics;

/// <summary>
/// Produces a redacted, stable string representation of an exception.
/// Keeps only the exception type FQN, module, method, HResult/Win32 code,
/// and at most 20 stack frames. Source file paths, line numbers, exception
/// messages, inner exception data, and Exception.Data are removed.
///
/// Known exception types are mapped to stable public codes (enum values)
/// so that telemetry can be classified without parsing free-form strings.
/// </summary>
public static class SanitizedExceptionFormatter
{
    private const int MaxFrames = 20;

    /// <summary>
    /// Maps known exception types to a stable diagnostic code.
    /// Unknown exceptions map to <see cref="Application.Diagnostics.DiagnosticCode.ScanFailed"/>.
    /// </summary>
    public static Application.Diagnostics.DiagnosticCode MapToDiagnosticCode(Exception ex)
    {
        return ex switch
        {
            OperationCanceledException or TaskCanceledException =>
                Application.Diagnostics.DiagnosticCode.ScanCancelled,

            InvalidOperationException => Application.Diagnostics.DiagnosticCode.ScanFailed,
            ArgumentException or ArgumentNullException or ArgumentOutOfRangeException =>
                Application.Diagnostics.DiagnosticCode.ScanFailed,
            TimeoutException => Application.Diagnostics.DiagnosticCode.ScanFailed,
            System.Net.Http.HttpRequestException => Application.Diagnostics.DiagnosticCode.ScanFailed,
            System.IO.IOException => Application.Diagnostics.DiagnosticCode.ScanFailed,
            Microsoft.Data.Sqlite.SqliteException => Application.Diagnostics.DiagnosticCode.ScanFailed,
            _ => Application.Diagnostics.DiagnosticCode.ScanFailed,
        };
    }

    /// <summary>
    /// Returns a stable, redacted string for the exception suitable for
    /// diagnostic events. Never includes Exception.Data, command-line
    /// arguments, environment variables, or inner exception details.
    /// </summary>
    public static string Format(Exception ex)
    {
        var sb = new StringBuilder(512);

        AppendExceptionInfo(sb, ex);

        // Append up to 20 frames, no source paths or line numbers.
        var trace = new StackTrace(ex, fNeedFileInfo: false);
        int frameCount = Math.Min(trace.FrameCount, MaxFrames);

        for (int i = 0; i < frameCount; i++)
        {
            StackFrame? frame = trace.GetFrame(i);
            if (frame is null) continue;

            var method = frame.GetMethod();
            if (method is null) continue;

            string module = method.Module?.Name ?? "?";
            string declaringType = method.DeclaringType?.FullName ?? "?";
            string methodName = method.Name;

            sb.Append(CultureInfo.InvariantCulture, $"  at {declaringType}.{methodName} [{module}]");
            if (i < frameCount - 1) sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns only the stable exception info line (type, module, HResult)
    /// without any stack frames.
    /// </summary>
    public static string FormatExceptionInfo(Exception ex)
    {
        var sb = new StringBuilder(256);
        AppendExceptionInfo(sb, ex);
        return sb.ToString();
    }

    private static void AppendExceptionInfo(StringBuilder sb, Exception ex)
    {
        string typeName = ex.GetType().FullName ?? ex.GetType().Name;
        string module = ex.TargetSite?.Module?.Name ?? "?";
        string method = ex.TargetSite?.DeclaringType is { } dt
            ? $"{dt.FullName}.{ex.TargetSite.Name}"
            : "?.?";

        int hResult = ex.HResult;

        sb.Append(CultureInfo.InvariantCulture,
            $"{typeName} module={module} method={method} hresult=0x{hResult:x8}");

        // Include Win32 error code if available (non-zero)
        int win32Code = ex.HResult & 0x0000FFFF;
        if (win32Code is not 0 and not unchecked((int)0x80131500 & 0x0000FFFF))
        {
            sb.Append(CultureInfo.InvariantCulture, $" win32={win32Code}");
        }
    }
}
