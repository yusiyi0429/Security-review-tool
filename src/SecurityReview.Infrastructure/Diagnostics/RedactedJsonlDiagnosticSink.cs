using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecurityReview.Application.Diagnostics;

namespace SecurityReview.Infrastructure.Diagnostics;

/// <summary>
/// Persistent <see cref="IDiagnosticSink"/> that validates every event
/// through <see cref="DiagnosticFieldPolicy"/>, serializes validated events
/// as UTF-8 JSONL, and rotates files at 10 MiB (keeping 5 files / 30 days).
///
/// Policy violations cause the field (or event) to be dropped and increment
/// an in-memory counter; no rejected data is persisted.
///
/// Output files are ACL-restricted to the current user on Windows.
/// Worker-payload <c>ToString</c> output is never logged.
/// </summary>
public sealed class RedactedJsonlDiagnosticSink : IDiagnosticSink, IDisposable
{
    private const long MaxFileBytes = 10L * 1024 * 1024; // 10 MiB
    private const int MaxFiles = 5;
    private const int MaxRetentionDays = 30;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly string _baseDirectory;
    private readonly string _filePrefix;
    private readonly object _writeLock = new();

    private string _currentFilePath = string.Empty;
    private FileStream? _currentStream;
    private StreamWriter? _currentWriter;
    private long _currentFileBytes;

    private long _policyViolationCount;
    private long _eventDroppedCount;

    /// <summary>
    /// Number of fields or events dropped due to policy violations.
    /// </summary>
    public long PolicyViolationCount => Volatile.Read(ref _policyViolationCount);

    /// <summary>
    /// Number of complete events dropped (all fields rejected).
    /// </summary>
    public long EventDroppedCount => Volatile.Read(ref _eventDroppedCount);

    public RedactedJsonlDiagnosticSink(string baseDirectory, string filePrefix = "diagnostics")
    {
        _baseDirectory = baseDirectory ?? throw new ArgumentNullException(nameof(baseDirectory));
        _filePrefix = filePrefix;

        Directory.CreateDirectory(_baseDirectory);
        CleanOldFiles();
        OpenNextFile();

        ApplyCurrentUserAcl(_baseDirectory);
    }

    /// <inheritdoc/>
    public void Publish(DiagnosticEvent diagnosticEvent)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEvent);

        // Validate the event against the field policy
        PolicyValidationResult result = DiagnosticFieldPolicy.ValidateEvent(diagnosticEvent);
        if (!result.IsValid)
        {
            Interlocked.Increment(ref _policyViolationCount);
            if (result.Violations.Count >= 3)
            {
                // Too many violations — drop the entire event
                Interlocked.Increment(ref _eventDroppedCount);
                return;
            }
        }

        // Build a sanitized JSON object
        string json;
        try
        {
            json = SerializeSanitizedEvent(diagnosticEvent);
        }
        catch
        {
            Interlocked.Increment(ref _eventDroppedCount);
            return;
        }

        byte[] lineBytes = Encoding.UTF8.GetBytes(json + "\n");

        lock (_writeLock)
        {
            // Rotate if the current file would exceed the limit
            if (_currentFileBytes + lineBytes.Length > MaxFileBytes && _currentFileBytes > 0)
            {
                CloseCurrent();
                CleanOldFiles();
                OpenNextFile();
            }

            if (_currentStream is null || _currentWriter is null)
            {
                Interlocked.Increment(ref _eventDroppedCount);
                return;
            }

            _currentStream.Write(lineBytes, 0, lineBytes.Length);
            _currentStream.Flush();
            _currentFileBytes += lineBytes.Length;
        }
    }

    /// <summary>
    /// Flushes and closes the current file. Thread-safe.
    /// </summary>
    public void Flush()
    {
        lock (_writeLock)
        {
            _currentWriter?.Flush();
            _currentStream?.Flush(flushToDisk: true);
        }
    }

    /// <summary>
    /// Returns the path of the current output file for bundle export.
    /// </summary>
    public string GetCurrentFilePath()
    {
        lock (_writeLock)
        {
            return _currentFilePath;
        }
    }

    public void Dispose()
    {
        lock (_writeLock)
        {
            CloseCurrent();
        }
    }

    private void OpenNextFile()
    {
        string timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        _currentFilePath = Path.Combine(_baseDirectory, $"{_filePrefix}-{timestamp}.jsonl");
        _currentStream = new FileStream(_currentFilePath, FileMode.CreateNew, FileAccess.Write,
            FileShare.Read, bufferSize: 4096, FileOptions.SequentialScan);
        _currentWriter = new StreamWriter(_currentStream, Encoding.UTF8, bufferSize: 4096) { AutoFlush = false };
        _currentFileBytes = 0;

        ApplyCurrentUserAcl(_currentFilePath);
    }

    private void CloseCurrent()
    {
        try
        {
            _currentWriter?.Flush();
            _currentWriter?.Dispose();
        }
        catch { }

        try
        {
            _currentStream?.Flush();
            _currentStream?.Dispose();
        }
        catch { }

        _currentWriter = null;
        _currentStream = null;
        _currentFilePath = string.Empty;
        _currentFileBytes = 0;
    }

    private void CleanOldFiles()
    {
        try
        {
            if (!Directory.Exists(_baseDirectory)) return;

            var files = new List<(string Path, DateTimeOffset Created)>();
            foreach (string file in Directory.EnumerateFiles(_baseDirectory, $"{_filePrefix}-*.jsonl"))
            {
                files.Add((file, File.GetCreationTimeUtc(file)));
            }

            // Sort by creation time, newest first
            files.Sort((a, b) => b.Created.CompareTo(a.Created));

            // Delete files older than 30 days
            DateTimeOffset cutoff = DateTimeOffset.UtcNow.AddDays(-MaxRetentionDays);
            foreach (var (path, created) in files)
            {
                if (created < cutoff)
                {
                    try { File.Delete(path); } catch { }
                }
            }

            // Keep at most MaxFiles beyond the cutoff
            var toKeep = files.Where(f => f.Created >= cutoff).Take(MaxFiles).Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var (path, _) in files)
            {
                if (!toKeep.Contains(path))
                {
                    try { File.Delete(path); } catch { }
                }
            }
        }
        catch
        {
            // Best-effort cleanup — never throw from a sink.
        }
    }

    private string SerializeSanitizedEvent(DiagnosticEvent evt)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false, Encoder = JsonOptions.Encoder });

        writer.WriteStartObject();
        writer.WriteString("code", evt.Code.ToString());
        writer.WriteString("utc", evt.UtcTimestamp.ToString("O", CultureInfo.InvariantCulture));

        if (evt.ScanId is { } scanId)
            writer.WriteString("scan_id", scanId.Value.ToString("N"));

        if (!string.IsNullOrEmpty(evt.CorrelationId))
            writer.WriteString("correlation_id", evt.CorrelationId);

        // Write fields — only those that pass the field policy
        writer.WriteStartObject("fields");
        SerializeFields(writer, evt.Fields);
        writer.WriteEndObject();

        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private void SerializeFields(Utf8JsonWriter writer, DiagnosticFields fields)
    {
        var properties = typeof(DiagnosticFields).GetProperties();
        foreach (var prop in properties)
        {
            string key = ToSnakeCase(prop.Name);
            if (!DiagnosticFieldPolicy.IsFieldAllowed(key)) continue;

            object? value = prop.GetValue(fields);
            if (value is null) continue;

            // Field value safety check
            if (value is string s && !DiagnosticFieldPolicy.IsFieldValueSafe(key, s))
            {
                Interlocked.Increment(ref _policyViolationCount);
                continue;
            }

            WriteJsonValue(writer, key, value);
        }
    }

    private static void WriteJsonValue(Utf8JsonWriter writer, string key, object value)
    {
        switch (value)
        {
            case string s:
                writer.WriteString(key, s);
                break;
            case int i:
                writer.WriteNumber(key, i);
                break;
            case long l:
                writer.WriteNumber(key, l);
                break;
            case bool b:
                writer.WriteBoolean(key, b);
                break;
            case double d:
                writer.WriteNumber(key, d);
                break;
            default:
                // Unsupported types are dropped
                break;
        }
    }

    private static string ToSnakeCase(string pascalCase)
    {
        return System.Text.RegularExpressions.Regex.Replace(pascalCase, "([a-z])([A-Z])", "$1_$2").ToLowerInvariant();
    }

    private static void ApplyCurrentUserAcl(string path)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        try
        {
            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists) return;

            var security = fileInfo.GetAccessControl();
            // Remove inherited permissions and grant only current user
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            if (currentUser is not null)
            {
                var rule = new System.Security.AccessControl.FileSystemAccessRule(
                    currentUser,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);
                security.AddAccessRule(rule);
            }

            fileInfo.SetAccessControl(security);
        }
        catch
        {
            // ACL enforcement is best-effort; never throw from a sink.
        }
    }
}
