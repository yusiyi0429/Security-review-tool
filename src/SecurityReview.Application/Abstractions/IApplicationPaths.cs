namespace SecurityReview.Application.Abstractions;

/// <summary>
/// Provides deterministic filesystem paths for the application's data layout.
/// </summary>
public interface IApplicationPaths
{
    string BasePath { get; }
    string Config { get; }
    string Data { get; }
    string Rules { get; }
    string Temp { get; }
    string Diagnostics { get; }
    string Backups { get; }
    string DatabaseFile { get; }
    string KeyRingFile { get; }

    /// <summary>Creates all application directories.</summary>
    void EnsureCreated();
}
